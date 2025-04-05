import struct
import lz4.frame
import os

hardnested_sums = [0, 32, 56, 64, 80, 96, 104, 112, 120, 128, 136, 144, 152, 160, 176, 192, 200, 224, 256]
hardnested_nonces_sum_map = []
hardnested_first_byte_num = 0
hardnested_first_byte_sum = 0


class Crypto1State:
    def __init__(self, key):
        self.odd = 0
        self.even = 0
        self.crypto1_init(key)

    def crypto1_init(self, key):
        #print(f"crypto1_init: key={key:012x}")
        for i in range(47, 0, -2):
            self.odd = (self.odd << 1) | ((key >> ((i - 1) ^ 7)) & 1)
            self.even = (self.even << 1) | ((key >> (i ^ 7)) & 1)
        #print(f"crypto1_init: odd={self.odd:08x}, even={self.even:08x}")

    def crypto1_bit(self, in_bit, is_encrypted):
        ret = self.filter(self.odd)
        #print(f"crypto1_bit: ret={ret}, odd={self.odd:08x}, even={self.even:08x}, in_bit={in_bit}, is_encrypted={is_encrypted}")
        feedin = ret & is_encrypted
        feedin ^= in_bit
        feedin ^= (0x29CE5C & self.odd)
        feedin ^= (0x870804 & self.even)
        self.even = (self.even << 1) | (self.evenparity32(feedin))
        t = self.odd
        self.odd = self.even
        self.even = t
        return ret

    def crypto1_byte(self, in_byte, is_encrypted):
        ret = 0
        #print(f"crypto1_byte: in_byte={in_byte:02x}, is_encrypted={is_encrypted}")
        for i in range(8):
            ret |= self.crypto1_bit((in_byte >> i) & 1, is_encrypted) << i
        #print(f"crypto1_byte: ret={ret:02x}")
        return ret

    def crypto1_word(self, in_word, is_encrypted):
        ret = 0
        #print(f"crypto1_word: in_word={in_word:08x}, is_encrypted={is_encrypted}")
        for i in range(32):
            ret |= self.crypto1_bit((in_word >> (i ^ 24)) & 1, is_encrypted) << (i ^ 24)
        #print(f"crypto1_word: ret={ret:08x}")
        return ret

    def filter(self, x):
        f = (0xf22c0 >> (x & 0xf)) & 16
        f |= (0x6c9c0 >> ((x >> 4) & 0xf)) & 8
        f |= (0x3c8b0 >> ((x >> 8) & 0xf)) & 4
        f |= (0x1e458 >> ((x >> 12) & 0xf)) & 2
        f |= (0x0d938 >> ((x >> 16) & 0xf)) & 1
        return (0xEC57E80A >> f) & 1

    def evenparity32(self, x):
        x ^= x >> 16
        x ^= x >> 8
        x ^= x >> 4
        x ^= x >> 2
        x ^= x >> 1
        return x & 1


def check_nonce_unique_sum(nt, par):
    """
    Check nt_enc is unique and calc first byte sum
    Pay attention: thread unsafe!!!
    @param nt - NT_ENC
    @param par - parity of NT_ENC
    """
    global hardnested_first_byte_sum, hardnested_first_byte_num
    first_byte = nt >> 24
    if not hardnested_nonces_sum_map[first_byte]:
        hardnested_first_byte_sum += Crypto1State.evenparity32((nt & 0xff000000) | (par & 0x08))
        hardnested_nonces_sum_map[first_byte] = True
        hardnested_first_byte_num += 1


def load_bitflip_tables(directory="hardnested_tables"):
    """Loads bitflip tables from a compressed binary file in the specified directory."""
    bitflip_table = {}
    script_dir = os.path.dirname(os.path.abspath(__file__))
    tables_dir = os.path.join(script_dir, directory)

    if not os.path.exists(tables_dir):
        raise FileNotFoundError(f"Error: Directory '{tables_dir}' not found.")

    for filename in os.listdir(tables_dir):
        if filename.endswith(".bin.lz4"):
            filepath = os.path.join(tables_dir, filename)
            try:
                with open(filepath, "rb") as f:
                    compressed_data = f.read()
                    decompressed_data = lz4.frame.decompress(compressed_data)
                    for i in range(0, len(decompressed_data), 3):
                        key = decompressed_data[i]
                        value = struct.unpack(">H", decompressed_data[i + 1:i + 3])[0]
                        bitflip_table[key] = value
            except Exception as e:
                raise RuntimeError(f"Error loading bitflip table '{filename}': {e}")
    return bitflip_table


def generate_keystream(state, length):
    """Generates a keystream of a given length."""
    keystream = []
    for _ in range(length):
        keystream.append(state.crypto1_bit(0, 0))
    return keystream


def test_key_candidate(key_candidate, nonces, responses, bitflip_table):
    """Tests a key candidate against the collected nonces and responses."""
    #print(f"test_key_candidate: key_candidate={key_candidate:012x}")
    state = Crypto1State(key_candidate)

    # Simulate the authentication process
    for nonce, response in zip(nonces, responses):
        # Generate keystream for the nonce
        keystream_nonce = state.crypto1_word(nonce, True)
        #print(f"test_key_candidate: nonce={nonce:08x}, keystream_nonce={keystream_nonce:08x}, response={response:08x}")

        # Check if the keystream matches the response
        if keystream_nonce != response:
            return False  # Key candidate is incorrect

    return True  # Key candidate is correct


def recover_key(nonces, responses, bitflip_table_directory="hardnested_tables"):
    """Recovers the key using the Hardnested attack."""
    bitflip_table = load_bitflip_tables(bitflip_table_directory)
    if bitflip_table is None:
        return None

    # Iterate through potential key candidates (simplified brute-force)
    for key_candidate in range(2 ** 48):  # 48-bit key
        #print(f"recover_key: Trying key_candidate={key_candidate:012x}")
        if test_key_candidate(key_candidate, nonces, responses, bitflip_table):
            # Convert the integer key to bytes
            print(f"recover_key: Found key_candidate={key_candidate:012x}")
            return f"{key_candidate:012x}"

    return None  # Key not found


def reset():
    """
    Resets the global variables.
    """
    global hardnested_first_byte_sum, hardnested_first_byte_num, hardnested_nonces_sum_map
    # clear the history
    hardnested_nonces_sum_map = list()
    for i in range(256):
        hardnested_nonces_sum_map.append(False)
    hardnested_first_byte_sum = 0
    hardnested_first_byte_num = 0

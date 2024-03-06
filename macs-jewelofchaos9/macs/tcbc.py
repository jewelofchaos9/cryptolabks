from .mac import MAC
from .utils import (
    xor,
    aes_block_encrypt,
    BLOCK_LENGTH
)


TRUNC = 8


class TCBC(MAC):
    def __init__(self, key):
        if len(key) != BLOCK_LENGTH:
            raise ValueError(f"Key len should be equal BLOCK_LENGTH {BLOCK_LENGTH}")

        self.key = key
        self.last_block = b'\x00' * BLOCK_LENGTH
        self.data = b''

    def __add_one_block(self, block: bytes):
        if len(block) != BLOCK_LENGTH:
            raise ValueError(f"can only work data block of length {BLOCK_LENGTH}")

        self.last_block = aes_block_encrypt(self.key, xor(self.last_block, block))

    def mac_add_block(self, data_block):
        self.data += data_block
        if len(self.data) <= BLOCK_LENGTH:
            # caching only ~BLOCK_LENGTH bytes
            return

        blocks_count = len(self.data) // BLOCK_LENGTH
        block_rems = len(self.data) % BLOCK_LENGTH

        for block_index in range(0, blocks_count):
            m_i = self.data[block_index * BLOCK_LENGTH: (block_index + 1) * BLOCK_LENGTH]
            self.__add_one_block(m_i)

        self.data = self.data[blocks_count*BLOCK_LENGTH:]

    def mac_finalize(self):
        last_part = self.data
        last_part += bytes([128])

        if len(last_part) % BLOCK_LENGTH != 0:
            last_part += bytes([0] *(BLOCK_LENGTH - len(last_part) % BLOCK_LENGTH))

        self.__add_one_block(last_part)

        data = self.last_block
        self.reset()
        return data[:TRUNC]

    def compute_mac(self, data):
        self.mac_add_block(data)
        return self.mac_finalize()

    def verify_mac(self, data, mac):
        return self.compute_mac(data) == mac

    def reset(self):
        self.data = b''
        self.need_to_finalize = False
        self.last_block = b'\x00' * BLOCK_LENGTH

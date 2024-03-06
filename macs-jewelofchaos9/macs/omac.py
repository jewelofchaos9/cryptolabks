from .mac import MAC
from .utils import (
    xor,
    aes_block_encrypt,
    BLOCK_LENGTH
)


class OMAC(MAC):
    def __init__(self, key):
        if len(key) != BLOCK_LENGTH:
            raise ValueError(f"Key len should be equal BLOCK_LENGTH {BLOCK_LENGTH}")

        self.k1, self.k2 = self.__generate_subkeys(key)
        self.key = key
        self.last_block = b'\x00' * BLOCK_LENGTH
        self.data = b''


    def __generate_subkeys(self, key):
        const_zero = b'\x00' * BLOCK_LENGTH
        const_rb = 0x87

        L = aes_block_encrypt(key, const_zero)
        l = int.from_bytes(L, 'big')

        # msb
        if l >> 127 == 0:
            k1 = (l << 1) & (8**BLOCK_LENGTH - 1)
        else:
            k1 = (l << 1) & (8**BLOCK_LENGTH - 1)
            k1 ^= const_rb

        # wtf in rfc need to find msb of k1 which bit length is not defined
        # is it nist backdoor ?
        if bin(k1)[2:][::-1] == '1':
            k2 = (k1 << 1) & (8**BLOCK_LENGTH - 1)
        else:
            k2 = (k1 << 1) & (8**BLOCK_LENGTH - 1)
            k2 ^= const_rb

        return (
            k1.to_bytes(BLOCK_LENGTH, 'big'),
            k2.to_bytes(BLOCK_LENGTH, 'big')
        )

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

        self.data = self.data[blocks_count * BLOCK_LENGTH:]

    def mac_finalize(self):
        block_rems = len(self.data) % BLOCK_LENGTH

        if block_rems == 0 and len(self.data) != 0:
            data = self.data
            m_n = xor(self.k1, data)
            self.__add_one_block(m_n)
        else:
            last_uncompleted_block = self.data
            last_uncompleted_block += bytes([128])
            last_uncompleted_block = last_uncompleted_block.ljust(BLOCK_LENGTH, b'\x00')
            m_n = xor(self.k2, last_uncompleted_block)
            self.__add_one_block(m_n)

        tag = self.last_block
        self.reset()

        return tag

    def compute_mac(self, data):
        self.mac_add_block(data)
        return self.mac_finalize()

    def verify_mac(self, data, mac):
        return self.compute_mac(data) == mac

    def reset(self):
        self.data = b''
        self.last_block = b'\x00' * BLOCK_LENGTH

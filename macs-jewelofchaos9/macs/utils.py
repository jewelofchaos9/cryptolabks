from Crypto.Cipher import AES


def xor(a, b):
    if len(a) != len(b):
        raise ValueError("Cannot xor not equal length")

    return bytes([i ^ j for i, j in zip(a, b)])


BLOCK_LENGTH = 16


class MetaSingleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(MetaSingleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class AESProxy(metaclass=MetaSingleton):
    def __init__(self):
        self.key = None
        self.aes = None

    def __update_aes(self):
        self.aes = AES.new(self.key, AES.MODE_ECB)

    def set_key(self, key):
        if key != self.key:
            self.key = key
            self.__update_aes()

    def encrypt(self, data):
        return self.aes.encrypt(data)


def aes_block_encrypt(key: bytes, block: bytes):
    if len(key) != BLOCK_LENGTH:
        raise ValueError(f"Wrong key length ({len(key)})")
    if len(block) != BLOCK_LENGTH:
        raise ValueError(f"Wrong block length ({len(block)})")

    aes = AESProxy()
    aes.set_key(key)

    return aes.encrypt(block)

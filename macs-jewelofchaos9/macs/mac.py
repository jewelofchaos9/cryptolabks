from abc import ABC
from hashlib import sha256

HASH_FUNCTION = sha256


class MAC(ABC):
    def __init__(self, key):
        raise NotImplementedError

    def mac_add_block(self, data_block: bytes):
        raise NotImplementedError

    def mac_finalize(self):
        raise NotImplementedError

    def compute_mac(self, data: bytes):
        raise NotImplementedError

    def verify_mac(self, data: bytes, mac: bytes):
        raise NotImplementedError

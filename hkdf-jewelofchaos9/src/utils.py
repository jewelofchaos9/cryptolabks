from hashlib import sha256


def xor(a, b):
    if len(a) != len(b):
        raise ValueError("Cannot xor not equal length")

    return bytes([i ^ j for i, j in zip(a, b)])


def ceil(a: float):
    b, l = str(a).split('.')
    adding = 1 if int(l[0]) >= 5 else 0

    return int(b) + adding


b = 64
ipad = bytes([0x36] * b)
opad = bytes([0x5c] * b)
L = 32


def hmac_sha256(key: bytes, data: bytes):
    # как тебе такое, pep8???
    # inner class, взятый с предыдущей лабки, для инкапсуляции

    class HMAC():
        def __init__(self, key: bytes):
            if len(key) == b:
                self.k_0 = key
            elif len(key) > b:
                self.k_0 = sha256(key).digest().ljust(b, b'\x00')
            else:
                self.k_0 = key.ljust(b, b'\x00')

            S_0 = xor(opad, self.k_0)
            S_i = xor(ipad, self.k_0)
            self.state = sha256()
            self.state.update(S_0)

            self.right_state = sha256()
            self.right_state.update(S_i)

            self.H = lambda x: self.state.update(x)

        def mac_finalize(self):
            self.state.update(self.right_state.digest())
            mac = self.state.digest()

            S_0 = xor(opad, self.k_0)
            S_i = xor(ipad, self.k_0)
            self.state = sha256()
            self.state.update(S_0)
            self.right_state = sha256()
            self.right_state.update(S_i)

            return mac

        def _mac_add_block(self, data: bytes):
            self.right_state.update(data)

        def compute_mac(self, data: bytes):
            self._mac_add_block(data)
            return self.mac_finalize()

        def mac_add_block(self, data: bytes):
            """Supposed to be limits to block, but it stupid"""
            self._mac_add_block(data)

        def verify_mac(self, data: bytes, mac: bytes):
            computed = self.compute_mac(data)
            return computed == mac

    hmac = HMAC(key)

    return hmac.compute_mac(data)

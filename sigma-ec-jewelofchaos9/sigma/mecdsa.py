from ecdsa import SigningKey, VerifyingKey
import ecdsa

G = ecdsa.keys.ecdsa.generator_192
curve = ecdsa.NIST192p.curve


def load_point_from_string(point_str: str):
    return G.from_bytes(
        curve, bytes.fromhex(point_str)
    )


class ECDSA:
    def __init__(self):
        pass

    def generate_keys(self):
        self.private_key = SigningKey.generate()
        self.public_key = self.private_key.verifying_key

    def sign(self, m: str):
        return self.private_key.sign(bytes.fromhex(m)).hex()

    def verify(self, m: str, s: str):
        return self.public_key.verify(bytes.fromhex(s), bytes.fromhex(m))

    def get_private_key(self):
        if not hasattr(self, 'private_key'):
            raise ValueError("Keys not initialized")

        return self.private_key.privkey.secret_multiplier


def verify_ecdsa(m: str, s: str, public_key_str: str):
    vk = VerifyingKey.from_public_point(
        load_point_from_string(public_key_str)
    )
    return vk.verify(bytes.fromhex(s), bytes.fromhex(m))

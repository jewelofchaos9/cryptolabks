import ecdsa

G = ecdsa.keys.ecdsa.generator_192
curve = ecdsa.NIST192p.curve


def load_point_from_string(point_str: str):
    return G.from_bytes(
        curve, bytes.fromhex(point_str)
    )


class ECDH:
    def __init__(self, private_key: int):
        self.base_point = G
        self.base_order = int(G.order())

        self.public_key = G * private_key
        self.private_key = private_key

    def get_public_key(self):
        return self.public_key.to_bytes().hex()

    def compute_shared_secret(self, other_public: str):
        other_public_point = load_point_from_string(other_public)

        return (other_public_point * self.private_key).to_bytes().hex()

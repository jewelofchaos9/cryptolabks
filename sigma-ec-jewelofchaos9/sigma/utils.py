from Crypto.Random import get_random_bytes
import hmac
from hashlib import sha256


R = 128
SYMMETRIC_KEY_SIZE = 16


def get_keys_from_prf(key, msg):
    data = hmac.new(bytes.fromhex(key), bytes.fromhex(msg), digestmod=sha256).digest()
    return data[:SYMMETRIC_KEY_SIZE], data[SYMMETRIC_KEY_SIZE:]


def get_random():
    return get_random_bytes(R//8).hex()


def compute_hmac(key, msg):
    return hmac.new(bytes.fromhex(key), bytes.fromhex(msg), digestmod=sha256).hexdigest()


def verify_hmac(key, msg, token):
    return hmac.new(bytes.fromhex(key), bytes.fromhex(msg), digestmod=sha256).hexdigest() == token

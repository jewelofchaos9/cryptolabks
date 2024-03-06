from Crypto.Cipher import AES
import hmac
from hashlib import sha256

AES_BLOCK_SIZE = 16
HMAC_SIZE = 32
NONCE_SIZE = 8
KEY_LENGTH = 32

class AEADEncryptor:
    def __init__(self, key: bytes):
        if len(key) != KEY_LENGTH:
            raise ValueError("Wrong key length")
        self.key = key[:KEY_LENGTH//2]
        self.encryptor = AES.new(self.key, AES.MODE_CTR)
        self.encrypted_data = self.encryptor.nonce

        self.hmac_key = key[KEY_LENGTH//2:]
        self.hmac = hmac.new(self.hmac_key, digestmod=sha256)
        self.hmac.update(self.encryptor.nonce)

    def add_block(self, data, is_final=False):
        enc = self.encryptor.encrypt(data)
        self.hmac.update(enc)
        self.encrypted_data += enc
        if is_final:
            return self.finalize_encryption()

    def finalize_encryption(self):
        data = self.encrypted_data
        token = self.hmac.digest()

        self.encryptor = AES.new(self.key, AES.MODE_CTR)
        self.hmac = hmac.new(self.hmac_key, digestmod=sha256)
        self.encrypted_data = b''

        return data + token

    def encrypt(self, data):
        return self.add_block(data, is_final=True)


class AEADDecryptor:
    def __init__(self, key: bytes):
        if len(key) != KEY_LENGTH:
            raise ValueError("Wrong key length")

        self.decrypted_data = b''
        self.key = key[:KEY_LENGTH//2]

        self.hmac_key = key[KEY_LENGTH//2:]
        self.nonce = None
        self.hmac = hmac.new(self.hmac_key, digestmod=sha256)

        self.collected_data = b''

    def add_block(self, data, is_final=False):
        # данный блок кода отвечает за то чтобы поточто распарсить nonce в ct 
        # простите меня
        if self.nonce is None:
            prev_length = len(self.collected_data)
            if len(data) + prev_length >= NONCE_SIZE:
                self.nonce = self.collected_data + data[:NONCE_SIZE - prev_length]
                data = data[NONCE_SIZE - prev_length:]
            elif len(data) >= NONCE_SIZE and self.collected_data == b'':
                self.nonce = data[:NONCE_SIZE]
                data = data[NONCE_SIZE:]
            else:
                self.collected_data += data
                return

            self.hmac.update(self.nonce)
            self.decryptor = AES.new(self.key, AES.MODE_CTR, nonce=self.nonce)

        if is_final:
            auth_code = data[-HMAC_SIZE:]

            self.hmac.update(data[:-HMAC_SIZE])
            self.decrypted_data += self.decryptor.decrypt(data[:-HMAC_SIZE])
            token = self.hmac.digest()

            if token != auth_code:
                raise ValueError("Bad auth code")

            dec = self.decrypted_data
            self.decrypted_data = b''
            self.decryptor = AES.new(self.key, AES.MODE_CTR, nonce=self.nonce)
            self.hmac = hmac.new(self.hmac_key, digestmod=sha256)

            return dec

        self.hmac.update(data)
        dec = self.decryptor.decrypt(data)
        self.collected_data += dec

    def decrypt(self, data):
        return self.add_block(data, is_final=True)


def main():
    from os import urandom
    key = urandom(KEY_LENGTH)
    aead_encryptor = AEADEncryptor(key)

    m1 = urandom(1024*1024*10)
    c1 = aead_encryptor.encrypt(m1)

    aead_decryptor = AEADDecryptor(key)

if __name__ == "__main__":
    main()



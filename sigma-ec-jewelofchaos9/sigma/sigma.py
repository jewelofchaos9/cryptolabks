from dataclasses import dataclass
from .mecdsa import ECDSA, verify_ecdsa
from .ecdh import ECDH
from .aead import AEADDecryptor, AEADEncryptor
from .utils import (
    compute_hmac,
    verify_hmac,
    get_random,
    get_keys_from_prf
)


@dataclass
class ClientHello:
    client_dh_pubkey: str
    client_random_string: str


@dataclass
class KeyExchangePackageClient:
    certificate_msg: str
    signed_public_keys: str
    mac_of_cert: str


@dataclass
class KeyExchangePackageServer:
    dh_pubkey: str
    random_string: str
    certificate_msg: str
    signed_public_keys: str
    mac_of_public_cert: str


class Client:
    def __init__(self, cert=b'i am client'):
        self.ecdsa = ECDSA()
        self.ecdsa.generate_keys()
        self.ecdh = ECDH(self.ecdsa.get_private_key())
        self.random = get_random()
        self.is_ready_to_communicate = False
        self.cert = cert

    def client_hello_msg(self) -> ClientHello:
        return ClientHello(
            self.ecdh.get_public_key(),
            self.random
        )

    def client_kex_msg(self) -> KeyExchangePackageClient:
        if not hasattr(self, 'k_m'):
            raise ValueError("Client must send kex after receiveng kex from server")

        return KeyExchangePackageClient(
            self.cert.hex(),
            self.ecdsa.sign(self.server_dh_pubkey + self.ecdh.get_public_key()),
            compute_hmac(self.k_m.hex(), self.cert.hex())
        )

    def __validate_server_kex_package(self, kex_package: KeyExchangePackageServer):
        dh_a_dh_b = self.ecdh.get_public_key() + kex_package.dh_pubkey

        if not verify_ecdsa(dh_a_dh_b, kex_package.signed_public_keys, kex_package.dh_pubkey):
            raise ValueError("Malformed ecdsa sign in kex package from server")

        if not verify_hmac(self.k_m.hex(), kex_package.certificate_msg, kex_package.mac_of_public_cert):
            raise ValueError("Malformed mac of certificate in kex package from server")

    def generate_keys(self, kex_package: KeyExchangePackageServer):
        r_b = kex_package.random_string
        r_ab = self.random + r_b
        shared_secret_temp = self.ecdh.compute_shared_secret(kex_package.dh_pubkey)
        self.k_m, self.k_e = get_keys_from_prf(r_ab, shared_secret_temp)
        self.server_dh_pubkey = kex_package.dh_pubkey

        self.__validate_server_kex_package(kex_package)
        self.is_ready_to_communicate = True

    def receive_message(self, msg):
        if not self.is_ready_to_communicate:
            raise ValueError("Trying to communicate without exchange")

        decryptor = AEADDecryptor(self.k_e + self.k_m)
        msg = bytes.fromhex(msg)

        return decryptor.decrypt(msg)

    def send_message(self, msg):
        if not self.is_ready_to_communicate:
            raise ValueError("Trying to communicate without exchange")
        encryptor = AEADEncryptor(self.k_e + self.k_m)
        msg = bytes.fromhex(msg)

        return encryptor.encrypt(msg)


class Server:
    def __init__(self, cert=b'i am server'):
        self.ecdsa = ECDSA()
        self.ecdsa.generate_keys()
        self.ecdh = ECDH(self.ecdsa.get_private_key())
        self.random = get_random()
        self.is_ready_to_communicate = False
        self.cert = cert

    def server_kex_msg(self) -> KeyExchangePackageServer:
        if not hasattr(self, "k_m"):
            raise ValueError("Server must send kex after receiveng hello from client")

        return KeyExchangePackageServer(
            self.ecdh.get_public_key(),
            self.random,
            self.cert.hex(),
            self.ecdsa.sign(self.client_dh_pubkey + self.ecdh.get_public_key()),
            compute_hmac(self.k_m.hex(), self.cert.hex())
        )

    def generate_keys(self, client_hello_msg: ClientHello):
        r_ab = client_hello_msg.client_random_string + self.random
        shared_secret_temp = self.ecdh.compute_shared_secret(client_hello_msg.client_dh_pubkey)
        self.k_m, self.k_e = get_keys_from_prf(r_ab, shared_secret_temp)

        self.client_dh_pubkey = client_hello_msg.client_dh_pubkey

    def accept_client_kex(self, kex_package: KeyExchangePackageClient):
        dh_b_dh_a = self.ecdh.get_public_key() + self.client_dh_pubkey
        if not verify_ecdsa(dh_b_dh_a, kex_package.signed_public_keys, self.client_dh_pubkey):
            raise ValueError("Malformed ecdsa sign in kex package from client")

        if not verify_hmac(self.k_m.hex(), kex_package.certificate_msg, kex_package.mac_of_cert):
            raise ValueError("Malformed mac of certificate in kex package from client")

        self.is_ready_to_communicate = True

    def receive_message(self, msg):
        if not self.is_ready_to_communicate:
            raise ValueError("Trying to communicate without exchange")
        decryptor = AEADDecryptor(self.k_e + self.k_m)
        msg = bytes.fromhex(msg)

        return decryptor.decrypt(msg)

    def send_message(self, msg):
        if not self.is_ready_to_communicate:
            raise ValueError("Trying to communicate without exchange")
        encryptor = AEADEncryptor(self.k_e + self.k_m)
        msg = bytes.fromhex(msg)

        return encryptor.encrypt(msg)

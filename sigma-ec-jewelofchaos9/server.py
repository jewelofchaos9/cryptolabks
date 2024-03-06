#!/usr/bin/python3

from dataclasses import asdict
import json
from sigma import Server, ClientHello, KeyExchangePackageClient


class SigmaPingServer:
    def __init__(self):
        self.server = Server()

    def recv_client_hello(self, msg: str):
        msg = json.loads(msg)
        client_hello = ClientHello(**msg)
        self.server.generate_keys(client_hello)

    def send_server_kex(self) -> str:
        return json.dumps(asdict(self.server.server_kex_msg()))

    def recv_client_kex(self, msg: str):
        msg = json.loads(msg)
        client_kex = KeyExchangePackageClient(**msg)
        self.server.accept_client_kex(client_kex)

    def recv_message(self, msg: str):
        return self.server.receive_message(msg)

    def send_message(self, msg: str):
        return self.server.send_message(msg)


def ping_sigma_server():
    server = SigmaPingServer()
    print("Your hello:")
    server.recv_client_hello(input())
    print(f"My kex\n{server.send_server_kex()}")
    print("Your kex:")
    server.recv_client_kex(input())

    print("Ready for communicate!!!")
    while True:
        print(f"Your message:")
        recv = server.recv_message(input())
        print(f"I received {recv}")
        print(f"Pinging it back:")
        print(server.send_message(recv.hex()).hex())

if __name__ == "__main__":
    ping_sigma_server()

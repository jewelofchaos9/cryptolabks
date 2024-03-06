from pwn import *
from sigma import Client, KeyExchangePackageServer
import json
from dataclasses import asdict
import time

p = process('./server.py')
client = Client()

print(p.recvline().decode())
p.sendline(
    json.dumps(
        asdict(client.client_hello_msg())
    ).encode()
)
print(p.recvline().decode())
client.generate_keys(
    KeyExchangePackageServer(**json.loads(p.recvline().decode()))
)

print(p.recvline().decode())

p.sendline(
    json.dumps(
        asdict(client.client_kex_msg())
    ).encode()
)

print(p.recvline())

while True:
    p.recvline()
    msg = input("client> ").encode().hex()
    ct = client.send_message(msg)
    p.sendline(ct.hex())
    print(p.recvline().decode())
    p.recvline()
    ans = p.recvline().decode()
    print(f"{ans = }")
    print(f"decoded message on client = {client.receive_message(ans).decode()}")

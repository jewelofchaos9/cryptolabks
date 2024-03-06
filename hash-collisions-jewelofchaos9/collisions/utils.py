from hashlib import sha256
from bitstring import BitArray
from dataclasses import dataclass


@dataclass
class CollisionStats:
    l_bound: int
    u_bound: int
    collision: tuple
    time_ns: int
    memory: int

    def __str__(self):
        return f"""Found collision {self.l_bound}:{self.u_bound} bits with {self.time_ns = },  {self.memory = } x = {self.collision[0].hex()}, y = {self.collision[1].hex()}"""


def truncate(m: bytes, l_bound: bytes, u_bound: bytes):
    h = BitArray(bytes=m).bin

    return h[l_bound: u_bound]


def truncated_sha256(m: bytes, l_bound: bytes, u_bound: bytes):
    return truncate(sha256(m).digest(), l_bound, u_bound)

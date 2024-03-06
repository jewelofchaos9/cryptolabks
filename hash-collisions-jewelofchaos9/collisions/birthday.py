from .utils import (
    truncated_sha256,
    CollisionStats
)
from time import time_ns
from os import urandom

SIZE = 16


def find_collision(l_bound, u_bound):
    time_start = time_ns()

    S = dict()
    while True:
        x = urandom(SIZE)

        h = truncated_sha256(x, l_bound, u_bound)
        if S.get(h, None) is not None:
            collision = (x, S.get(h))
            break

        S[h] = x

    return CollisionStats(
        l_bound,
        u_bound,
        collision,
        time_ns() - time_start,
        len(S.keys()) * (u_bound - l_bound) * 8 + len(S.keys()) * SIZE
    )

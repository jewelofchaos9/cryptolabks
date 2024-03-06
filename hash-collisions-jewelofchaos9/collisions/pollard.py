from .utils import (
    CollisionStats,
    truncated_sha256
)
from os import urandom
from bitstring import BitArray
from math import log2
from time import time_ns
import concurrent.futures


S = dict()
THREADS = 3
K = 500
SIZE = 32


def check_if_distinguished(y, q):
    return set(BitArray(bytes=y).bin[:q//2]) == {'0'}


def PI(m):
    bin_data = BitArray(bytes=m).bin + '0' * K
    pad_length = 0 if len(bin_data) % 8 == 0 else 8 - len(bin_data) % 8
    pad = '0' * (pad_length) + bin_data
    return BitArray(bin=pad).bytes


def H(m, l_bound, u_bound):
    bin_data = truncated_sha256(m, l_bound, u_bound)
    pad_length = 0 if len(bin_data) % 8 == 0 else 8 - len(bin_data) % 8
    pad = '0' * (pad_length) + bin_data
    return BitArray(bin=pad).bytes


class PollardThread:
    def __init__(self, l_bound, u_bound):
        self.i = 0
        self.q = int((u_bound - l_bound) / 2 - log2(THREADS))
        self.y = urandom(16)
        self.id_y = self.y
        self.l_bound = l_bound
        self.u_bound = u_bound

    def __find_in_set(self, y):
        return S.get(y, None)

    def H(self, y):
        return H(y, self.l_bound, self.u_bound)

    def run(self):
        while True:
            self.i += 1
            self.y = PI(self.H(self.y))
            if not check_if_distinguished(self.y, self.q):
                continue

            other_thread_info = self.__find_in_set(self.y)
            if other_thread_info is not None:
                return (
                    (self.id_y, self.y, self.i),
                    (other_thread_info[0], self.y, other_thread_info[1])
                )

            S[self.y] = (self.id_y, self.i)


def find_col(data1, data2, l_bound, u_bound):
    i, j = data1[2], data2[2]
    if i < j:
        data2, data1 = data1, data2

    i, j = data1[2], data2[2]
    d = i - j
    y = data1[0]
    z = data2[0]
    for i in range(d):
        y = PI(H(y, l_bound, u_bound))

    while True:
        if H(y, l_bound, u_bound) == H(z, l_bound, u_bound):
            return y, z
        y = PI(H(y, l_bound, u_bound))
        z = PI(H(z, l_bound, u_bound))


def find_collision(l_bound, u_bound):
    global S
    threads = [PollardThread(l_bound, u_bound) for _ in range(THREADS)]
    start = time_ns()
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as pool:
        futures = [pool.submit(thread.run) for thread in threads]
        first_completed = concurrent.futures.wait(futures, return_when=concurrent.futures.FIRST_COMPLETED)
        match = first_completed.done.pop().result()
    pool.shutdown(wait=False)

    collision = find_col(match[0], match[1], l_bound, u_bound)
    len_s = len(S)
    S = dict()

    return CollisionStats(
        l_bound,
        u_bound,
        collision,
        time_ns() - start,
        len_s * (4 + (u_bound - l_bound) // 8 + 4)
    )


if __name__ == "__main__":
    #data = find_collision(0, 8)
    data = find_collision(0, 9)
    print('aasd')
    x, y = data.collision
    print(H(x, 0, 9), H(y, 0, 9))

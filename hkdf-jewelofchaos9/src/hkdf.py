from .utils import (
    hmac_sha256,
    ceil,
    L,
    xor
)


def hkdf_extract(xts: bytes, skm: bytes):
    return hmac_sha256(xts, skm)


def hkdf_expand(prk: bytes, last_key: bytes, ctx: bytes, i: int):
    # Странно, что мы добавляем ключ
    # Возможно же, что у хэша есть линейные структуры, которые дадут какую то информацию о исходном ключe
    # Тем более, что для случайности мы добавляем индекс и контекст...
    last_key += prk
    last_key += ctx
    last_key += i.to_bytes(4, 'big')

    return hkdf_extract(prk, last_key)


def F(P, S, c, i, PRF=hmac_sha256):
    first = PRF(P, S + i.to_bytes(4, 'big'))
    base = first
    last = first
    for i in range(c):
        last = PRF(P, last)
        base = xor(base, last)

    return base


def pbkdf2(master_password, salt, iterations, dk_len, PRF=hmac_sha256):
    l = ceil(dk_len/L)
    r = dk_len - (l - 1) * L

    T = []
    for i in range(l):
        T.append(F(master_password, salt, iterations, i + 1))

    res = b''.join(T[:-1])
    res += T[-1][:r]

    return res


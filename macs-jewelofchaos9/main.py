from macs import HMAC as HMAC_OWN, OMAC, TCBC
from hashlib import sha256
from os import urandom
import time


def test_hmac():
    import hmac
    own = HMAC_OWN(b'Swordwish')
    data = b'asdfasdfasdf'
    norm = hmac.new(b'Swordwish', msg=data, digestmod=sha256)

    assert norm.digest() == own.compute_mac(data)
    own = HMAC_OWN(b'Swordwish')
    own.mac_add_block(b'asdfasdf')
    own.mac_add_block(b'asdfasdf')
    assert own.mac_finalize() == HMAC_OWN(b'Swordwish').compute_mac(b'asdfasdfasdfasdf')

    own = HMAC_OWN(b'Swordwish')
    own.mac_add_block(b'asdfasdf')
    own.mac_add_block(b'asdfasdf')
    mac = own.mac_finalize()
    assert own.verify_mac(b'asdfasdfasdfasdf', mac)

    mac = list(mac)
    mac[0] = 1
    assert not own.verify_mac(b'asdfasdfasdfasdf', bytes(mac))


def test_omac():
    #omac = OMAC(b'asdfasdfasdfasdf')
    #tag = omac.compute_mac(b'abobus')
    #assert omac.verify_mac(b'abobus', tag)
    #tag = list(tag)
    #tag[0] = 1
    #assert not omac.verify_mac(b'abobus', bytes(tag))

    omac = OMAC(b'asdfasdfasdfasdf')
    omac2 = OMAC(b'asdfasdfasdfasdf')

    omac.mac_add_block(b'aboba' * 5)
    omac.mac_add_block(b'aboba' * 5)

    assert omac.mac_finalize() == omac2.compute_mac(b'aboba' * 10)



def test_tcbc():
    tcbc = TCBC(b'asdfasdfasdfasdf')
    tag = tcbc.compute_mac(b'abobus')
    assert tcbc.verify_mac(b'abobus', tag)

    mac = list(tag)
    mac[0] = 1
    assert not tcbc.verify_mac(b'abobus', bytes(mac))


def test_mac(mac, size=1024, tries=10):
    start = time.time_ns()
    for _ in range(tries):
        msg = urandom(size)
        mac.compute_mac(msg)

    return (time.time_ns() - start) / tries


def get_timings():
    hmac = HMAC_OWN(urandom(16))
    omac = OMAC(urandom(16))
    tcbc = TCBC(urandom(16))

    sizes = [10, 1000, 10 * 1024, 1024*1024]
    hmac_timings = []
    for size in sizes:
        hmac_timings.append(test_mac(hmac, size=size))

    omac_timings = []
    for size in sizes:
        omac_timings.append(test_mac(omac, size=size))

    tcbc_timings = []
    for size in sizes:
        tcbc_timings.append(test_mac(tcbc, size=size))

    return hmac_timings, omac_timings, tcbc_timings

def test_orig_hmac(size=1024, tries=10):
    import hmac
    start = time.time_ns()
    for _ in range(tries):
        msg = urandom(size)
        hmac.new(b'asdf', msg=msg, digestmod=sha256)

    return (time.time_ns() - start) / tries


def compute_original_hmac_timings():
    sizes = [10, 1000, 10 * 1024, 1024*1024]
    hmac_orig_timings = []
    for size in sizes:
        hmac_orig_timings.append(test_orig_hmac(size=size))

    return hmac_orig_timings


def visualize():
    import matplotlib.pyplot as plt
    h, o, t = get_timings()
    print(h, o, t)
    fig, ax = plt.subplots()
    x = [10, 1000, 10 * 1024, 1024*1024]


    for i in range(len(h)):
        h[i] /= 10**6
        o[i] /= 10**6
        t[i] /= 10**6
        x[i] /= 1000

    ax.plot(x, o, label="omac")
    ax.plot(x, t, label="tcbc")
    ax.set_xlabel("KBytes")
    ax.set_ylabel("Time, ms")
    ax.legend()
    fig.savefig('timings_omac_tcbc.png')

    hmac_orig_timings = compute_original_hmac_timings()
    for i in range(len(h)):
        hmac_orig_timings[i] /= 10**6

    fig, ax = plt.subplots()
    ax.plot(x, h, label="Hmac_own")
    ax.plot(x, hmac_orig_timings, label="Hmac_original")
    ax.set_xlabel("Bytes")
    ax.set_ylabel("Time, ms")
    ax.legend()
    fig.savefig('timings_hmac.png')



if __name__ == "__main__":
    test_hmac()
    test_omac()
    test_tcbc()
    visualize()

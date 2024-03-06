from collisions import birthday_find_collision, truncated_sha256, pollard_find_collision
from hashlib import sha256
from bitstring import BitArray


def test_truncate():
    assert BitArray(bin=truncated_sha256(b'asdf', 0, 24)).bytes == sha256(b'asdf').digest()[:3]
    assert BitArray(bin=truncated_sha256(b'asdf', 24, 48)).bytes == sha256(b'asdf').digest()[3:6]


def test_birthday():
    l_bound = 16
    u_bound = 24

    collision_info = birthday_find_collision(240, 256)
    print(str(collision_info))
    x, y = collision_info.collision
    assert sha256(x).digest()[-2:] == sha256(y).digest()[-2:]


def test_pollard():
    l_bound = 16
    u_bound = 24

    collision_info = pollard_find_collision(240, 256)
    print(str(collision_info))
    x, y = collision_info.collision
    assert sha256(x).digest()[-2:] == sha256(y).digest()[-2:]


def get_pollard_info(size, tries=5):
    avg = 0
    avg_mem = 0
    for _ in range(tries):
        coll = pollard_find_collision(256-size, 256)
        avg += coll.time_ns
        avg_mem += coll.memory


    return avg/tries, avg_mem/ tries


def get_birthday_info(size, tries=5):
    avg = 0
    avg_mem = 0
    for _ in range(tries):
        coll = birthday_find_collision(256-size, 256)
        avg += coll.time_ns
        avg_mem += coll.memory

    return avg/tries, avg_mem/tries


def visualize():
    import matplotlib.pyplot as plt

    pollard = []
    pollard_mem = []
    birthday = []
    birtday_mem = []
    sizes = list(range(9, 36, 2))
    for size in sizes:
        print(size)
        time_ns, mem = get_pollard_info(size)
        pollard.append(time_ns / 10**6)
        pollard_mem.append(mem/1024)
        time_ns, mem = get_birthday_info(size)
        birthday.append(time_ns / 10 ** 6)
        birtday_mem.append(mem/1024)

    fig, ax = plt.subplots()
    x = sizes
    ax.plot(x, pollard, label="pollard")
    ax.set_xlabel("BITS")
    ax.set_ylabel("Time, ms")
    ax.legend()
    fig.savefig('timings_pollard.png')

    fig, ax = plt.subplots()
    x = sizes
    ax.plot(x, birthday, label="birthday")
    ax.set_xlabel("BITS")
    ax.set_ylabel("Time, ms")
    ax.legend()
    fig.savefig('timings_birthday.png')

    fig, ax = plt.subplots()
    x = sizes
    ax.plot(x, birtday_mem, label="birthday")
    ax.set_xlabel("BITS")
    ax.set_ylabel("Memory, KB")
    ax.legend()
    fig.savefig('memory_birthday.png')

    fig, ax = plt.subplots()
    x = sizes
    ax.plot(x, pollard_mem, label="pollard")
    ax.set_xlabel("BITS")
    ax.set_ylabel("Memory, KB")
    ax.legend()
    fig.savefig('memory_pollard.png')


def save_max_collisions():
    f = open('./cols.txt', 'w')
    for i in range(100):
        print(i)
        col1 = birthday_find_collision(0, 35)
        col2 = pollard_find_collision(0, 35)
        f.write(str(col1) + '\n')
        f.write(str(col2) + '\n')
    f.close()


if __name__ == "__main__":
    test_truncate()
    test_birthday()
    test_pollard()
    visualize()
    #save_max_collisions()

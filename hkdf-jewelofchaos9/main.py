import json
import matplotlib.pyplot as plt
from os import urandom
from src import (
    hkdf_expand,
    hkdf_extract,
    pbkdf2
)


def visualize_parsed(data, name="Temperature"):
    plt.hist(data, bins=15, color='skyblue', edgecolor='black')
    plt.xlabel(name)
    plt.ylabel('Frequency')

    plt.savefig(f"{name}.png")
    plt.clf()


def visualize_weather():
    with open('./weather.json', 'r') as f:
        data = json.loads(f.read())
    data = data['hourly']['data']
    temperatures = []
    humidities = []
    wind_speeds = []
    cloud_covers = []
    ozones = []
    for hour_data in data:
        temperatures.append(hour_data['temperature'])
        humidities.append(hour_data['humidity'])
        wind_speeds.append(hour_data['windSpeed'])
        cloud_covers.append(hour_data['cloudCover'])
        ozones.append(hour_data['ozone'])

    visualize_parsed(temperatures, 'temp')
    visualize_parsed(humidities, 'humidity')
    visualize_parsed(wind_speeds, 'wind_speed')
    visualize_parsed(cloud_covers, 'cloud_cover')
    visualize_parsed(ozones, 'ozone')


def temperature_to_bytes(temperature):
    # Я думал что здесь будет классная почти биективная функция в байт, но в этом нет смысла...
    # Это же никак не повлияет на распределение величины
    return str(temperature).encode()


def visualize_hkdf():
    with open('./weather.json', 'r') as f:
        data = json.loads(f.read())
    data = data['hourly']['data']
    temperatures = []
    for hour_data in data:
        temperatures.append(hour_data['temperature'])

    data = b''
    for temp in temperatures:
        data += temperature_to_bytes(temp)

    salt = urandom(1337)
    key_material = hkdf_extract(salt, data)

    keys = []
    last_key = b''
    for i in range(1, 1001):
        last_key = hkdf_expand(key_material, last_key, b'absolutely_in_context', i)
        keys.append(last_key)

    first_ten_bits = []
    for key in keys:
        t = key[0]
        t <<= 2
        t2 = key[1] >> 6
        t |= t2
        first_ten_bits.append(t)

    visualize_parsed(first_ten_bits, "Ten_bits_distribution")

def visualize_pbkdf2():
    with open('./passwords.json', 'r') as f:
        data = json.loads(f.read())

    password_first_bits = []
    for password in data:
        t = password.encode()[0] & 0b11111000
        password_first_bits.append(t)

    visualize_parsed(password_first_bits, "first_five_password_bits_distr")

    keys = []
    passwords = [password.encode() for password in data]
    for password in passwords:
        salt = urandom(1337)
        key = pbkdf2(password, salt, 10000, 512//8)
        keys.append(key)


    first_ten_bits = []
    for key in keys:
        t = key[0]
        t <<= 2
        t2 = key[1] >> 6
        t |= t2
        first_ten_bits.append(t)

    visualize_parsed(first_ten_bits, "Ten_bits_distribution_pbkdf2")






if __name__ == "__main__":
    #visualize_weather()
    #visualize_hkdf()
    visualize_pbkdf2()

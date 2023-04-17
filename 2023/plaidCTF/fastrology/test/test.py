import math
randoms = eval(open('test.txt', 'rb').read())
mult = 4
payloads = [math.floor(random * mult) for random in randoms]


def init(array):
    rets = []
    for i in range(0, len(array), 64):
        rets.extend(array[i:i+64][::-1])
    return rets


import new_xs128p
print(new_xs128p.solve_random(payloads[15:-128], 15, "", 4, ""))
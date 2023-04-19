from new_xs128p import *
import os
import math

b4 = [
    [0, 0],
    [0, 1],
    [1, 0],
    [1, 1],
]
seed = os.urandom(16)
original_state0, orginal_state1 = int.from_bytes(
    seed[:8], 'big'), int.from_bytes(seed[8:], 'big')
print("original seed: (%s, %s)" % (original_state0, orginal_state1))
rng = next_random(original_state0, orginal_state1)

randoms = [next(rng) for i in range(15 + 192 + 128)]
mult = 4
payloads = [math.floor(random * mult) for random in randoms]
print("Last 128 value of payloads:\n\t", payloads[-128:])


state0, state1 = solve_random(payloads[15:-128], 15, next_idx(), b4)
print("recovered seed: (%s, %s)" % (state0, state1))

new_rng = next_random(state0, state1)
for i in range(15 + 192):
    next(new_rng)
predict_random = [math.floor(next(new_rng)*mult) for i in range(128)]
print("Predicted value:\n\t", predict_random)
# import struct
# def from_double(dbl):
#     return struct.unpack('<Q', struct.pack('d', dbl + 1))[0] & 0x7FFFFFFFFFFFFFFF
# for i in range(13):
#     print(f"{from_double(i/13):064b}"[12:])
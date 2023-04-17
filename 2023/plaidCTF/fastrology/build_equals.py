from sage.all import GF, save, vector

F = GF(2)
def Add(a, b):
    assert len(a) == 64 and len(b) == 64
    c = []
    for i, j in zip(a, b):
        c.append(i + j)
    return c

def SL(a, n):
    assert len(a) == 64
    return a[n:] + [vector(F, 128)]*n


def SR(a, n):
    assert len(a) == 64
    return [vector(F, 128)]*n + a[:64 - n]


def sym_xs128p(sym_state0, sym_state1):
    # Symbolically represent xs128p
    s1 = sym_state0
    s0 = sym_state1
    s1 = Add(s1, SL(s1, 23))
    s1 = Add(s1, SR(s1, 17))
    s1 = Add(s1, s0)
    s1 = Add(s1, SR(s0, 26))
    return sym_state1, s1
F = GF(2)
v = [vector(F, [0]*i + [1] + [0]*(127-i)) for i in range(128)]
state0 = v[:64]
state1 = v[64:]
N = 64 + (250+128)*2
Bigg = []
for i in range(N):
    state0, state1 = sym_xs128p(state0, state1)
    Bigg.append(state0[:-12])

save(Bigg, f'equals')
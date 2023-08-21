from sage.all import *

res_str = 'eZ!gjyTdSLcJ3{!Y_pTcMqW7qu{cMoyb04JXFHUaXx{8gTCIwIGE-AAWb1_wu32{'
mul_str = 'HuuMKaxLVHVqC6NSB1Rwl2WC1F7zkxxrxAuZFpPogbBd4LGGgBfK9!eUaaSIuqJK'
Charcode = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ{_-!}'


def map_matrix(s):
    tmp = [Charcode.index(i) for i in s]
    res = []
    for i in range(0, 64, 8):
        res.append(tmp[i:i+8])
    return res


F = GF(len(Charcode))
n = 8  # dimension
A = matrix(F, map_matrix(res_str))
B = matrix(F, map_matrix(mul_str))

# Math thing
# https://math.stackexchange.com/questions/3028145/how-to-solve-ax-xb-for-x-matrix
# START
I = matrix.identity(F, n)
blocks = [
    [
        (A - B[i, j] * I) if i == j else (-B[j, i] * I)
        for j in range(n)
    ] for i in range(n)
]
Q = block_matrix(F, n, blocks)

sols = []
for sol in Q.right_kernel().basis():
    sol = matrix(F, n, sol).T
    assert A*sol == sol*B
    sols.append(sol.list())

known_flag = [18, 12, 29, 15, 62, 66, 0, 0]

coeffs = []
for flag_index in [0, 1, 2, 3, 4, 61, 62, 63]:
    coeffs.append([sol[flag_index] for sol in sols])

coeffs = matrix(F, coeffs)
v = vector(F, known_flag)
linear_comb = coeffs.solve_right(v)  # solve Ac = b
flag = sum(matrix(F, n, sol) * mult for sol, mult in zip(sols, linear_comb))
# END

assert A*flag == flag*B
print(''.join([Charcode[i] for i in flag.list()]))

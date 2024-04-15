from sage.all import *
from sympy import Float, Point, Triangle

def dps_to_prec(n):
    """Return the number of bits required to represent n decimals
    accurately."""
    return max(1, int(round((int(n)+1)*3.3219280948873626)))
PRECISION = 1337
PRECISION_B = dps_to_prec(1337)

D = 2**PRECISION_B
R = RealField(PRECISION_B)

def randFloat():
    return -1 + 2 * R(getrandbits(PRECISION)) / (1 << PRECISION)
def lift(x):
    return (x*D).round()

class RandomLine:
    def __init__(self):
        self.x = randFloat()
        self.y = randFloat()
        self.dx = randFloat()
        self.dy = randFloat()

    def __getitem__(self, i):
        return Point(self.x + self.dx * i, self.y + self.dy * i, evaluate=False)

    def print(self):
        print(self.x)
        print(self.y)
        print(self.dx)
        print(self.dy)
A = RandomLine()
B = RandomLine()
C = RandomLine()
# A.print()
# B.print()
# C.print()
i, j, k =[getrandbits(32) for _ in range(3)]
AA = A[i]
BB = B[j]
CC = C[k]
T = Triangle(A[i], B[j], C[k])
out1 = T.circumcenter

def func2(Points: list[Point], out: Point):
    
    ...
i, j, k = func2([A, B, C], out1)
print(i, j, k)
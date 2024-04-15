from sage.all import *
from sympy import Float, Point
from collections import namedtuple
from pwn import *
from fpylll import *


def dps_to_prec(n):
    return max(1, int(round((int(n)+1)*3.3219280948873626)))


PRECISION = 1337
PRECISION_B = dps_to_prec(1337)
D = 2**PRECISION_B
R = RealField(PRECISION_B)


class Line:
    def __init__(self, x, y, dx, dy):
        self.x = x
        self.y = y
        self.dx = dx
        self.dy = dy


def lift(x):
    return (x*D).round()


def create_lattice(pr, shifts, monomials=None, sort_shifts_reverse=False, sort_monomials_reverse=False):
    if monomials == None:
        monomials = set()
        for shift in shifts:
            monomials.update(shift.monomials())

    shifts.sort(reverse=sort_shifts_reverse)
    monomials = sorted(monomials, reverse=sort_monomials_reverse)
    L = matrix(pr.base_ring(), len(shifts), len(monomials))
    for row, shift in enumerate(shifts):
        for col, monomial in enumerate(monomials):
            L[row, col] = shift.monomial_coefficient(monomial)
    return L, monomials


def func1(Points: list[Line], O: Point):
    pr = R[','.join([f'x{idx}' for idx in range(len(Points))])]
    xs = pr.gens()

    def gen(A: Line, x):
        return A.x + x*A.dx
    poly = R(0)
    for x, _ in zip(xs, Points):
        poly += gen(_, x)
    poly -= R(3) * R(Float(O.x, PRECISION))

    L = len(poly.coefficients()) - 1
    mat = matrix(ZZ, list(map(lift, poly.coefficients()))).T
    mat = mat.augment(matrix.identity(L).stack(vector([0]*L)))
    return mat.LLL()[0][1:]


def func2(Points: list[Line], O: Point):
    pr = R[','.join([f'x{idx}' for idx in range(len(Points))])]
    xs = pr.gens()

    def sym(D: Line, O: Point, x):
        return (D.x + x*D.dx - O.x)**2 + (D.y + x*D.dy - O.y)**2
    poly = sym(Points[0], O, xs[0]) - sym(Points[1], O, xs[1])

    mom = set()
    mom.update(poly.monomials())
    cnt = 1
    while not set(xs).issubset(mom) and cnt < len(Points) - 1:
        cur = sym(Points[cnt], O, xs[cnt]) - sym(Points[cnt+1], O, xs[cnt+1])
        poly -= cur
        mom.update(cur.monomials())
        cnt += 1
    Lat, m = create_lattice(pr, [poly], mom, sort_monomials_reverse=True)
    mat = matrix(ZZ, [list(map(lift, L)) for L in Lat]).T
    mat = mat.augment(matrix.identity(len(m)-1).stack(vector([0]*(len(m)-1))))
    return mat.LLL()[0].list()[-len(Points):]


def func3(Points: list[Line], O: Point):
    pr = R[','.join([f'x{idx}' for idx in range(len(Points))])]
    xs = pr.gens()

    x, y = var('x y')
    i, j, k = var('i j k')
    x1, x2, x3, dx1, dx2, dx3 = var('x1 x2 x3 dx1 dx2 dx3')
    y1, y2, y3, dy1, dy2, dy3 = var('y1 y2 y3 dy1 dy2 dy3')

    a1 = (x2+dx2*j - (x1+dx1*i))
    a2 = -(y2+dy2*j - (y1+dy1*i))
    a3 = ((x1+dx1*i)*(y2+dy2*j-(y1+dy1*i)) - (y1+dy1*i)*(x2+dx2*j-(x1+dx1*i)))

    b1 = (x3+dx3*k - (x1+dx1*i))
    b2 = -(y3+dy3*k - (y1+dy1*i))
    b3 = ((x1+dx1*i)*(y3+dy3*k-(y1+dy1*i)) - (y1+dy1*i)*(x3+dx3*k-(x1+dx1*i)))

    eq = (b1*y+b2*x+b3)**2 * (a1**2+a2**2) - (a1*y+a2*x+a3)**2 * (b1**2+b2**2)

    eq1 = eq.substitute(x=O.x, y=O.y,
                        x1=Points[0].x, x2=Points[1].x,  x3=Points[2].x,
                        y1=Points[0].y, y2=Points[1].y,  y3=Points[2].y,
                        dx1=Points[0].dx, dx2=Points[1].dx, dx3=Points[2].dx,
                        dy1=Points[0].dy, dy2=Points[1].dy, dy3=Points[2].dy).expand()

    eq2 = eq.substitute(x=O.x, y=O.y,
                        x1=Points[2].x, x2=Points[0].x,  x3=Points[1].x,
                        y1=Points[2].y, y2=Points[0].y, y3=Points[1].y,
                        dx1=Points[2].dx, dx2=Points[0].dx, dx3=Points[1].dx,
                        dy1=Points[2].dy, dy2=Points[0].dy, dy3=Points[1].dy).expand()

    t = var('t')
    eq2 = eq2.substitute(j=t)
    eq2 = eq2.substitute(k=j)
    eq2 = eq2.substitute(t=k)

    eq2 = eq2.substitute(k=t)
    eq2 = eq2.substitute(i=k)
    eq2 = eq2.substitute(t=i)

    eq1 *= (1 << PRECISION_B)
    eq2 *= (1 << PRECISION_B)

    monomials1 = eq1.polynomial(R).monomials()
    monomials2 = eq2.polynomial(R).monomials()

    monomials = list(set(monomials1) | set(monomials2))
    monomials.sort(reverse=True)

    M = matrix.identity(ZZ, len(monomials))
    for i in range(len(monomials)):
        M[i, i] *= 2**(32*(6 - monomials[i].degree()))
        if i == len(monomials) - 1:
            M[i, i] = 2**(32*6 - 8)

    coeff_vec1 = eq1.polynomial(R).coefficients()
    coeff_vec2 = eq2.polynomial(R).coefficients()
    M = M.augment(vector(ZZ, [int(round(coeff_vec1[monomials1.index(
        mono)])) if mono in monomials1 else 0 for mono in monomials]))
    M = M.augment(vector(ZZ, [int(round(coeff_vec2[monomials2.index(
        mono)])) if mono in monomials2 else 0 for mono in monomials]))

    row = M.LLL()[0]
    if row[0] < 0:
        row *= -1
    i, j, k = row[-6] >> (32 * 5), row[-5] >> (32 * 5), row[-4] >> (32 * 5)

    return i, j, k


conn = process(["python", "chall.py"])


def recvFloat():
    return Float(conn.recvline().strip().decode("ascii"), PRECISION)


for solver in [func1, func2, func3]:
    conn.recvuntil(b"===== Challenge =====\n")
    lineA = Line(*[recvFloat() for _ in range(4)])
    lineB = Line(*[recvFloat() for _ in range(4)])
    lineC = Line(*[recvFloat() for _ in range(4)])

    ox = recvFloat()
    oy = recvFloat()

    i, j, k = solver([lineA, lineB, lineC], Point(ox, oy))
    log.success(f"Found: {i} {j} {k}")
    conn.sendlineafter(b"> ", f"{i} {j} {k}".encode())
conn.interactive()

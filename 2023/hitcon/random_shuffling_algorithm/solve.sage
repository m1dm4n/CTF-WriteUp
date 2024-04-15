from sage.all_cmdline import *
import sys
from Crypto.Util.number import long_to_bytes as ltb, bytes_to_long as btl, getPrime, getRandomRange
from tqdm import tqdm, trange
exec(open('./output.txt', 'r').read())
P = None
M = None
x = ZZ['x'].gens()[0]
for i in trange(100):
    f = ZZ(1)
    for a, b, c in cts[i]:
        f *= (a*x + b)**11 - c
    if i == 0:
        P = f
        M = pubs[i]
    else:
        P = crt(P, f, M, pubs[i])
        M = lcm(M, pubs[i])
ZM = Zmod(M)
P = P.change_ring(ZM)
from subprocess import check_output
from re import findall

def flatter(M):
    z = "[[" + "]\n[".join(" ".join(map(str, row)) for row in M) + "]]"
    ret = check_output(["flatter"], input=z.encode())
    return matrix(M.nrows(), M.ncols(), map(int, findall(b"-?\\d+", ret)))

def small_roots(f, X, beta=1.0, m=None):
    N = f.parent().characteristic()
    delta = f.degree()
    if m is None:
        epsilon = RR(beta^2/f.degree() - log(2*X, N))
        m = max(beta**2/(delta * epsilon), 7*beta/delta).ceil()
    t = int((delta*m*(1/beta - 1)).floor())
    print(m, t)
    
    f = f.monic().change_ring(ZZ)
    P,(x,) = f.parent().objgens()
    g  = [x**j * N**(m-i) * f**i for i in range(m) for j in range(delta)]
    g.extend([x**i * f**m for i in range(t)]) 
    B = Matrix(ZZ, len(g), delta*m + max(delta,t))

    for i in range(B.nrows()):
        for j in range(g[i].degree()+1):
            B[i,j] = g[i][j]*X**j
    print("do flatter")
    B =  flatter(B)
    print("done flatter")
    f = sum([ZZ(B[0,i]//X**i)*x**i for i in range(B.ncols())])
    roots = set([f.base_ring()(r) for r,m in f.roots() if abs(r) <= X])
    return [root for root in roots if N.gcd(ZZ(f(root))) >= N**beta]
beta = ZZ(8 * 127) * 44 / (1024 * 100)
print(small_roots(P, 2**1016, beta=0.44, m=1)) # degree 44 / 100
# [120039153147275612279226072293039199989969435136720881392074739490216237445596918586488417768801307603836543606827992369039948429370926261172805872470575886813016385668019620, 482392614478393528952831932035773242406955698425695406319950300997518912897501747016178383250788296360037466509997031885046058717408614085325714387503123667471421671002203194717363274516944761912241161992187572242484775989362923688152314218513920976429726225349017002285717480282794835061524817669847650035, 370158203601696356824744264837067510894209113191047227977499850782664475747970439023138065826563556729715926377142756987674583013786750809342391114409451950252073420793582063612594440290068567256251840598542169138848718712955165803898440243094140779328902332773023505371803736088449673219863398285033835901, 168657622158324664695093984693682814652346301197487495534293980942467580538704212715811816631856241319336663381746535651191837601535600164744216572123634505113088257836937538780591294079471868814767561135957049428082139679397962946605830934298942465378642696010130783461799846843611010085950596519162976117]
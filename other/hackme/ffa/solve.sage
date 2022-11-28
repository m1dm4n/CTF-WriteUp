from sage.all import *
# Set variables
out = {
    "p": 240670121804208978394996710730839069728700956824706945984819015371493837551238,
    "q": 63385828825643452682833619835670889340533854879683013984056508942989973395315,
    "M": 349579051431173103963525574908108980776346966102045838681986112083541754544269,
    "z": 213932962252915797768584248464896200082707350140827098890648372492180142394587,
    "m": 282832747915637398142431587525135167098126503327259369230840635687863475396299,
    "x": 254732859357467931957861825273244795556693016657393159194417526480484204095858,
    "y": 261877836792399836452074575192123520294695871579540257591169122727176542734080
}
p = out['p']
q = out['q']
M = out['M']
m = out['m']
x = out['x']
y = out['y']
z = out['z']
Fm = GF(m)
FM = GF(M)

# Using solver to find a, b, c
a, b, c = var('a b c')
po1 = ((a + b * 3)) == x
po2 = ((b - c * 5)) == y
po3 = ((a + c * 8)) == z
sol = solve([po1, po2, po3], a, b, c, solution_dict=True)[0]
print(sol)

# Find a, b, c in Finite Field m
a = Integer(Fm(sol[a]))
b = Integer(Fm(sol[b]))
c = Integer(Fm(sol[c]))
print(f'a = {a}')
print(f'b = {b}')
print(f'c = {c}')
assert is_prime(a) and is_prime(b) and is_prime(c)

# Find d such that flag^(a*d) = 1 (RSA)
d = inverse_mod(a, M - 1)
flag = int(FM(p) ^ d)
print("Flag:", flag.to_bytes((flag.bit_length() + 7) //
      8, byteorder='big').decode('utf8'))

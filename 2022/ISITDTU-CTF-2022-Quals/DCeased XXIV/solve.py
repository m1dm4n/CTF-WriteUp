from PIL import Image
from Untwister import Untwister

img1 = Image.open('out.png')
img2 = Image.open('part.png')


p1 = img1.load()
p2 = img2.load()
x_len, y_len = img1.size

R = Untwister()
def int2rgba(n):
	r, g, b, a = tuple([(n >> 8*i) & 0xff for i in range(3, -1, -1)])
	return (r, g, b, a)
def rgba2int(rgba: tuple):
	ret = 0
	for i in range(3, -1, -1):
		ret += rgba[i] << 8*(3 - i)
	return ret


def xor(a):
	return a[0] ^ a[1]
def xor_tuple(a, b):
	return tuple(i for i in map(xor, zip(*[a, b])))


new = Image.new('RGBA', (x_len, y_len), 'white')
px1 = new.load()

Tw = None
for x in range(x_len):
    n1 = rgba2int(p1[x, 0])
    n2 = rgba2int(p2[x, 0])
    R.submit(bin(n1^n2)[2:].zfill(32))
    if R.index >= 624:
	Tw = R.get_random()
	break

for y in range(y_len):
    for x in range(x_len):
        if y == 0 and x < 624:
            rand = rgba2int(p1[x, y])^rgba2int(p2[x, y])
        else:
            rand = Tw.getrandbits(32)
        rr, rg, rb, ra = int2rgba(rand)
        r, g, b, a = p1[x, y]
        new_pix = xor_tuple((rr, rg, rb, ra), (r, g, b, a))
        px1[x, y] = new_pix

new.save('flag.png')

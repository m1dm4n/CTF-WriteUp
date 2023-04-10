import os
import hashlib
import random

# FLAG = os.getenv('FLAG')
FLAG = b"PWNED"
KEY = os.urandom(32)


def H(b): return hashlib.sha256(b).digest()


def xor(a, b):
	return bytes(x ^ y for x, y in zip(a, b))


CREDS = b"print('\\nLogged in as guest.\\n')"
CREDS = CREDS + H(CREDS+KEY)

for _ in range(1337 + random.randint(0, 1000)):
	buf = CREDS
	b = xor(H(buf[:32]), buf[-32:])
	a = xor(H(b), buf[:32])
	CREDS = a + b

CREDS = CREDS.hex()

del H, xor
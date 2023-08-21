import random
yyyy = random.randint(1970, 2260)
mm   = random.randint(1, 12)
dd   = random.randint(1, 28)
HH   = random.randint(0, 23)
MM   = random.randint(0, 60)
SS   = random.randint(0, 60)
MS   = random.randint(0, 999999)
print(f"@{yyyy:04d}-{mm:02d}-{dd:02d} {HH:02d}:{MM:02d}:{SS:02d}.{MS:06d}")
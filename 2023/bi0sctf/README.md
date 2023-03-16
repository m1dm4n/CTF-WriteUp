layout: page
title: "bi0sctf"

# bi0sctf 2023

Since I don't have much time to do all the challenge so here is a short Write Up for 2 crypto challenges i had solve.

## Leakydsa

This is a Elliptic Curve Digital Signature Algorithm and the server give us 136 bits over 256 bits of nonce. So we have about 120 bits nonce unknown which is very small compare to order (256 bits)
=> A common HNP solving

Matrix to reduce:

$$
\begin{pmatrix}
-order & 0 & 0 & 0 \\
0 & -order & 0 & 0 \\
r1/s1 & r2/s2 & 2^{120}/order & 0 \\
z1/s1 - msb1 & z2/s2 - msb2 & 0 & 2^{120} \\
\end{pmatrix}
$$

Small vector after reduce:

$$
(lsb1, lsb2, (d*2^{120})/order, 2^{120})
$$

## Too EC

Another ECDSA with bad nonce but this time we have 2 curve and we must factorize `N`, which is `p1*p2` first, so that we could recover the order of 2 curve. `N` is so big but luckily the challenge also give us a partial factor of `N` which had been erased 3 small parts of its => Small modular roots of a multivariate polynomial

For solving a Coppersmith factorization, i had used script from [link](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/factorization/coppersmith.py) which run very fast on my laptop (about 25s). For remainder part of challenge is nearly same as previous Leakydsa chall

Matrix to reduce:

$$
\begin{pmatrix}
-order & 0 & 0 & 0 \\
0 & -order & 0 & 0 \\
r1/s1 & r2/s2 & 2^{128}/order & 0 \\
z1/s1 & z2/s2 & 0 & 2^{128} \\
\end{pmatrix}
$$

Small vector after reduce:

$$
(nonce1, nonce2, (d*2^{128})/order, 2^{128})
$$


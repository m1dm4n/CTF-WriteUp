# PBCTF 2023

I had spended many time on **HACKTM 2023** so i had solved 2 challenges **ecc2** and **Blocky5** after the contest ended


> detail writeups will have if i'm not lazy :)

## Solution

First ecc challenge had a smooth order on 1 of Elliptice Curve group, so just take that Curve then calculating discrete log of payload from server and we can predict next `state`


The second ecc challenge will make us to find a singular curve (bruteforcing `b` and wait for error since **sagemath's** EllipticCurve check its when you construct a curve) and then change the `BASE_POINT` in the server to our singular point. The remaining could easily solve when you have a singular curve (i used [this script](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/ecc/singular_curve.py))
 

For 2 challenges Blocky4 and Blocky5, i had written about it in here (https://hackmd.io/@m1dm4n/wannagame2022#AES-4-round). The 5 round version is just required us to bruteforce additional 3 bytes of the last round key.


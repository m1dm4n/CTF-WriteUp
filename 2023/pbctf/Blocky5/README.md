# Blocky5

**References**:
- https://www.davidwong.fr/blockbreakers/square_4_attack5rounds.html
- https://eprint.iacr.org/2012/280.pdf

The reason why i use 5 sets of ciphertexts instead 1 like Block4 is because for each key guess we alway have 1/243 chance to have a XOR sum equal 0, together with the thing that we also have to guess 3 bytes of last round key, the checking definitely always true. So with one single byte of the penultimate `MixColumnsInv(RoundKey)` and last 3 bytes round key, the 5 sets will be best optimize for the checking key guess of brutefocing 


Local running:

![image](https://user-images.githubusercontent.com/92845822/220879678-d6a3d131-7fc3-4c5b-b129-dec4e292d1b5.png)

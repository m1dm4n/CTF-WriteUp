# Cyber Apocalypse 2023 - The Cursed Mission

- [Cyber Apocalypse 2023 - The Cursed Mission](#cyber-apocalypse-2023---the-cursed-mission)
- [Crypto](#crypto)
  - [Elliptic Labyrinth Revenge](#elliptic-labyrinth-revenge)
  - [Biased Heritage](#biased-heritage)
  - [Converging Visions](#converging-visions)
  - [Blokechain](#blokechain)
- [Blockchain](#blockchain)
  - [Navigating the Unknown](#navigating-the-unknown)
  - [Shooting 101](#shooting-101)
  - [The Art of Deception](#the-art-of-deception)


# Crypto

## Elliptic Labyrinth Revenge

- [Source](https://github.com/m1dm4n/CTF-WriteUp/blob/main/2023/HTB_Cursed_Mission/crypto_elliptic_labyrinth_revenge.zip)

- [Script](https://github.com/m1dm4n/CTF-WriteUp/tree/main/2023/HTB_Cursed_Mission/crypto_elliptic_labyrinth)

We are given a random point on an random Elliptic Curve and we can request the server to give us $p$, $a >> r$, $b >> r$ with $r$ is a random number between 170 and 341.

From the Point that they give us, we will have an equation: $y^2 = x^3 + ax + b \pmod{p}$. Using partial information about $a$ and $b$, we can use Coppersmith method to find $r$ left significant bits of $a, b$ or you could reduce it to a Hidden** number problem** like me

Define $eq1 = y_A^2 - (x_A^3 + x_A * (a\_high * 2^r) + (b\_high * 2^r))$. Matrix to reduce:

$$
\begin{pmatrix} 
	eq1 & 2^r & 0 \\
	-x_A & 0 & 1 \\
	p & 0 & 0 \\
\end{pmatrix}
$$

The target vector when $r$ is small enough: $(b\_low, 2^r, a\_low)$

## Biased Heritage

- [Source](https://github.com/m1dm4n/CTF-WriteUp/blob/main/2023/HTB_Cursed_Mission/crypto_biased_heritage.zip)

- [Script](https://github.com/m1dm4n/CTF-WriteUp/tree/main/2023/HTB_Cursed_Mission/crypto_biased_heritage)

This challenge have a custom DSA and require us to forge a valid signature for the message `"right hand"`.

First thing i notice is that the nonce is not generated uniformly at random. The 'random' is a hash value of message concat with $x$ using sha256 so it only has 256 bits. Than it concat with itself to get the 512 bits value so we have this relation $k = k' * (2^{256} + 1)$ with k will be the nonce and k' is the sha256 value.

Using the infomation from sever, we have this equation:

$$
\begin{align}
s_i &= (2^{256} + 1)*k_i - x*e_i \pmod{q} \\
\Leftrightarrow k_i &= s_i/(2^{256} + 1) + x*e_i/(2^{256} + 1) \pmod{q}
\end{align}
$$

Since $k_i$ is small (256 bits), I will use the Hidden Number Problem to solve this biased nonces problem. Since we only have 2 samples for each session may be you coule use the coppersmith method (i didnt test it so i don't know it work or not :))

Matrix to reduce:

$$
\begin{pmatrix}
	q& 0 & 0 & 0 \\
	0 & q & 0 & 0 \\
	\frac{e_1}{(2^{256} + 1)} & \frac{e_2}{(2^{256} + 1)} & \frac{1}{2^{256}} & 0 \\
    \frac{s_1}{(2^{256} + 1)} & \frac{s_2}{(2^{256} + 1)} & 0 & 2^{256}
\end{pmatrix}
$$

The target vector we want after reducing: $(k_1, k_2, x/2^{256}, 2^{256})$. Because the number of payload we can get is small so the reduction not always work so you just connect to server multiple times and wait for lucky :)


## Converging Visions

- [Source](https://github.com/m1dm4n/CTF-WriteUp/blob/main/2023/HTB_Cursed_Mission/crypto_converging_visions.zip)

- [Script](https://github.com/m1dm4n/CTF-WriteUp/tree/main/2023/HTB_Cursed_Mission/crypto_converging_visions)

First you need to recover all parameters of Elliptic Curve on the server. No need to binary search, we can extract $k*p$ from 3 random points on Elliptic Curve, make it mutiple times then GCD all the $k*p$ to get $p$, after that we can easily extract $a, b$.  You can read about it in this Write up ([uiuctf-2020-nookcrypt](https://hackmd.io/@mystiz/uiuctf-2020-nookcrypt))

Then i notice that the order on the Elliptic Curve is equal to $p$ -> We can solve discrete log using [Smart Attack](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/ecc/smart_attack.py)

Although the value we get from dlog had been modulo with $p$ but the modulus of `PRNG` is a multiple of $p$ so it didn't effect anything. Just grab it, calculate square root and we have the seed, put it on PRNG and predict the next Point on the server.

## Blokechain

- [Source](https://github.com/m1dm4n/CTF-WriteUp/blob/main/2023/HTB_Cursed_Mission/crypto_blokechain.zip)

- [Script](https://github.com/m1dm4n/CTF-WriteUp/tree/main/2023/HTB_Cursed_Mission/crypto_blokechain)

Because the config is really suck, you could send 60 random number to get all the hash value and send all it back agian.

About my solution, I had recovered clauses which have most probability in each `functions` of the `PrivateHash`.

The `PrivateHash` is evaluating 100 boolean functions on the values for the 50 variables which is bit array of the input number. Each functions have 10 clause and the function will return True when 1 of the clauses is True. Each clause will True if some bits at some random index is '1' if the term is positive else '0', clause will be randomized when initing the Hash.

Only balanced boolean functions is using (mean the probability of True and False is approximate equal) but the probability of term in a clause is 0.5 (bit only have 0 and 1 value) so more term means the probability of a clause will decrease exponentially. This lead to 1 problem that the clause with 1, 2 or may be 3 terms is frequently appear in a function. 

By collecting a large number of input and output of the Hash and perform a frequency analysis at each position of input when a function is True, I can partial recover short clause like 1 or 2 terms(3 is quite rare so i will skip it) from some high statistical deviation. Function to recover a single `function`:

```python
def get_funcs_of_priv_hash(samples, real_anss):
    equal_1 = []
    for i in range(len(samples)):
        if real_anss[i] == 1:
            equal_1.append(samples[i])
    n1 = len(equal_1)

    clauses = []
    for i in range(50):
        cur = [equal_1[_][i] for _ in range(n1)]
        bit, c = Counter(cur).most_common(1)[0]
        clauses.append((i, bit, c))

    clauses = sorted(clauses, key=lambda e: e[2], reverse=True)
    # print(clauses)
    if clauses[0][2] > 0.9*n1:
        clauses = [[(a[0], a[1]) for a in clauses[:1]]]
    else:
        clauses = [(a[0], a[1]) for a in clauses[:4]]
        clauses = re_test(clauses, samples, real_anss)
    # print(clauses)
    # print()
    return clauses
```

The last `if else` is mean to check that if any index can impact more than 90% the output then i can use it as only clause for that that function, if not i need to re-test first 4 highest statistical deviation to get 2 pair that have most corrected probability. After recover 100 partial functions, I just do normal query to server, calculating the hash value and wait for lucky. 

Local testing prove that my solution have about 30% success rate on average so for each resets i will get around 1 milion. If your network is good enough to make the server check around 50 block number for you then you will get the flag.


# Blockchain

## Navigating the Unknown

- [Source](https://github.com/m1dm4n/CTF-WriteUp/blob/main/2023/HTB_Cursed_Mission/blockchain_navigating_the_unknown.zip)

- [Script](https://github.com/m1dm4n/CTF-WriteUp/tree/main/2023/HTB_Cursed_Mission/blockchain_navigating_the_unknown)

Call the `updateSensors` function with number `10` and done

## Shooting 101

- [Source](https://github.com/m1dm4n/CTF-WriteUp/blob/main/2023/HTB_Cursed_Mission/blockchain_shooting_101.zip)

- [Script](https://github.com/m1dm4n/CTF-WriteUp/tree/main/2023/HTB_Cursed_Mission/blockchain_shooting_101)

For this challenge you will need some knownledge about how contract understand your calldata.

- `firstShot`: You will need trigger fallback function (will trigger when it don't recognize any function's selector even the receive function if contract have it)

```solidity
(bool succ,) = target.call("bruh bruh lmao!");
```


- `secondShot`: receive function will trigger when no calldata is provided

```solidity
(bool succ,) = target.call("");
```

- `thirdTarget`: Simple call it when you successfully call two shots above

```
ShootingArea(target).third();
```

## The Art of Deception

- [Source](https://github.com/m1dm4n/CTF-WriteUp/blob/main/2023/HTB_Cursed_Mission/blockchain_the_art_of_deception.zip)

- [Script](https://github.com/m1dm4n/CTF-WriteUp/tree/main/2023/HTB_Cursed_Mission/blockchain_the_art_of_deception)

If we want to enter, we need to be a **Entrant** contract and support the `name` function. But **Entrant** is just define as an interface so we could easily control how the `name` function work.

The sanity check of the target contract:

```solidity
require(_isAuthorized(_entrant.name()), "Intruder detected");
lastEntrant = _entrant.name();
```

The target call `name` fuction 2 time so the logic is simple. Return valid name in the first call and then return name `"Pandora"` for the next call

```solidity
function name() external returns (string memory) {
    string memory ret;
    if (c == 0) {
        ret = "Orion";
        c = 1;
    }
    else {
        ret = "Pandora";
        c = 0;
    }
    return ret;
}
```

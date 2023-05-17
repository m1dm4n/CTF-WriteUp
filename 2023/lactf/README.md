# LACTF 2023 - Blockchain Writeups
## breakup

Source:
+ [Setup.sol](https://github.com/m1dm4n/CTF-WriteUp/tree/main/2023/lactf/breakup/Setup.sol)
+ [Friend.sol](https://github.com/m1dm4n/CTF-WriteUp/tree/main/2023/lactf/breakup/Friend.sol)

For this challenge, the main contract check if "You" is in `friendNames` of `Friend` contract so you need to delete the name "You" from the mapping. Solution is use the `burn` function of it since the key of "You" in the mapping is easy to get just from reading the source (call `tokenOfOwnerByIndex` with `somebodyYouUsedToKnow` address and value `0`)

My scipt: [solve.py](https://github.com/m1dm4n/CTF-WriteUp/blob/main/2023/lactf/breakup/solve.py)

## evmvm 

Source:
+ [Setup.sol](https://github.com/m1dm4n/CTF-WriteUp/tree/main/2023/lactf/evmvm/Setup.sol)
+ [EVMVM.sol](https://github.com/m1dm4n/CTF-WriteUp/tree/main/2023/lactf/evmvm/EVMVM.sol)


This challenge is harder since you need to understand how the solidity work in lower level of Solidy language (like assembly). The main contract requires the sender of who ever want to solve it is its deployed contract `EVMVM`. It means that we need to make the deployed `EVMVM` contract call the function `solve` of `Setup` contract to win.

![image](https://user-images.githubusercontent.com/92845822/218942091-143e4300-bffc-4543-952e-3c46f37838dd.png)

So our target will be the "EVMVM" contract, which have a function `enterTheMetametaverse` to executes a single opcode every times we send to it. This problem leads to a thing that we cannot use the memory of contract because memory is like RAM, the function end the ram clean. This is really a pain since if we want to make a call a function of another contract, we need a calldata contains singnature of function we want to call but look at this first.

`call` opcode document:

![image](https://user-images.githubusercontent.com/92845822/218943394-cb6c4195-023c-4dc8-ad29-031a31d41efd.png)

`call` opcode in `EVMVM` contract:

![image](https://user-images.githubusercontent.com/92845822/218943728-17b8208e-ef0e-4ec3-ba61-3135b8c2cc4e.png)

The call opcode requires the offset of calldata in memory and this offset is got from `stack`. We can save anything we want to the memory easily using `mstore` opcode but in the next calling it just disappear. I had been stuck from this step so i just do some guessing method but it didn't work because i'm still very new to blockchain. After the ctf ends, i learned that `delegatecall` is our solution. [What is DelegateCall in solidity](https://medium.com/coinmonks/delegatecall-calling-another-contract-function-in-solidity-b579f804178c)

Basically the `delegatecall` is something like this: 

> When contract A executes delegatecall to contract B , B's code is executed. with contract A's storage, `msg.sender` and `msg.value`. So if contract B make a call to contract C, the `msg.sender` will be A's `msg.sender`


With this, we can create our malicious contract that have a function to call function `solve` of `Solve` contract, then trigger a `delegatecall` from `EVMVM` contract to our contract and the `msg.sender` will be `EVMVM` contract. Our contract:

```solidity
contract Exploit {
    address immutable setup;

    constructor(address _setup) {
        setup = _setup;
    }
    fallback() external {
        setup.call(abi.encodeWithSignature("solve()"));
    }
}
```

> `fallback` is the function that will be called when the contract don't understand the function's signature, or when it's empty and don't have a `receive` function.

The harder thing is done, other part is just stack knowledge and programming skill. My solution is:

1. Push `36` to stack because the function still have a parameter `arg` and its index is 36 in the `calldata` we send to contract (the first 4 bytes is function signature and the next 32 bytes is the `opcode` parameter)
2. Now we can use `CALLDATALOAD` opcode to push anything we want to stack from `arg` param so just push all parameters of `DELEGATECALL`: `gas, address, 0, 0, 0, 0` (Read the document of its).
3. Send the opcode of `DELEGATECALL` and we are done!

> note1: the leftmost is the highest value in stack

> note2: `address` is our deployed contract

> note3: When call a function the EVM read parameters from right to left and then call it so we will need to push in reverse order

| Opcode name | Stack  |
| :---:       | :---- |
| CALLVALUE    | 0 |
| ISZERO       | 1 |
| DUP1         | 1 1 |
| SHL          | 2 |
| DUP1         | 2 2 |
| CALLDATASIZE | 68 2 2 |
| SWAP1        | 2 68 2 |
| DIV          | 34 2 |
| ADD          | 36 |
| DUP1         | 36 36 |
| CALLDATALOAD | gas 36 |
| SWAP1        | 36 gas |
| CALLDATALOAD | `address` `gas` |
| CALLVALUE    | 0 `address` `gas` |
| CALLVALUE    | 0 0 `address` `gas` |
| CALLVALUE    | 0 0 0 `address` `gas` |
| CALLVALUE    | 0 0 0 0 `address` `gas` |

Then sending the opcode of `delegatecall` and we are done. Output:

```python
[+] Pushing delegatecall's params to stack: Done
[DEBUG] stack size: 6
[DEBUG] 0x0 : 0x00000000000000000000000000000000000000000000000000000000000186a0
[DEBUG] 0x1 : 0x0000000000000000000000007ee24f4f9d8f0d6f5321228ebb0529422b0e813a
[DEBUG] 0x2 : 0x0000000000000000000000000000000000000000000000000000000000000000
[DEBUG] 0x3 : 0x0000000000000000000000000000000000000000000000000000000000000000
[DEBUG] 0x4 : 0x0000000000000000000000000000000000000000000000000000000000000000
[DEBUG] 0x5 : 0x0000000000000000000000000000000000000000000000000000000000000000
[*] Setup.functions.isSolved().call() = True
[+] Successfully exploiting!
```

My script: [solve.py](https://github.com/m1dm4n/CTF-WriteUp/blob/main/2023/lactf/evmvm/solve.py)

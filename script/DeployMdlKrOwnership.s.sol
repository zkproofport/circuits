// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.21;

import {Script, console} from "forge-std/Script.sol";
import {HonkVerifier} from "../mdl/kr-ownership/target/MdlKrOwnership.sol";

contract DeployMdlKrOwnership is Script {
    function run() external {
        vm.startBroadcast();
        HonkVerifier verifier = new HonkVerifier();
        console.log("MdlKrOwnership HonkVerifier:", address(verifier));
        vm.stopBroadcast();
    }
}

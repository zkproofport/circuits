// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.21;

import {Script, console} from "forge-std/Script.sol";
import {HonkVerifier} from "../mdl/kr-age/target/MdlKrAge.sol";

contract DeployMdlKrAge is Script {
    function run() external {
        vm.startBroadcast();
        HonkVerifier verifier = new HonkVerifier();
        console.log("MdlKrAge HonkVerifier:", address(verifier));
        vm.stopBroadcast();
    }
}

// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.21;

import {Script, console} from "forge-std/Script.sol";
import {HonkVerifier} from "../dojang-playground/target/DojangPlayground.sol";

contract DeployDojangPlayground is Script {
    function run() external {
        // The key comes from the environment, never the command line, where any
        // process listing shows it (deploy_verifier.sh exports PRIVATE_KEY).
        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        HonkVerifier verifier = new HonkVerifier();
        console.log("DojangPlayground HonkVerifier:", address(verifier));
        vm.stopBroadcast();
    }
}

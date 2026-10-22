// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.21;

import {Script, console} from "forge-std/Script.sol";
// Imported only so the artifact is compiled for vm.deployCode. The library is
// the same in every generated verifier of one bb version; deploy_verifier.sh
// deploys it from CoinbaseAttestation.sol.
import {ZKTranscriptLib} from "../coinbase-attestation/target/CoinbaseAttestation.sol";

/// Deploys the ZKTranscriptLib that every generated HonkVerifier links.
/// The key is read from PRIVATE_KEY in the environment: it used to be passed to
/// `forge create --private-key`, where a process listing showed it.
contract DeployTranscriptLib is Script {
    function run() external {
        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        address lib = vm.deployCode("CoinbaseAttestation.sol:ZKTranscriptLib");
        console.log("ZKTranscriptLib:", lib);
        vm.stopBroadcast();
    }
}

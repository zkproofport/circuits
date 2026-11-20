// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.21;

import {Script, console} from "forge-std/Script.sol";
// Imported only so the artifacts are compiled for vm.deployCode: a forge
// script sees the artifacts of its own imports and nothing else. The library
// code is the same in every verifier one bb writes (only the file's metadata
// differs), so CoinbaseAttestation.sol stands in for all of them;
// scripts/deploy_verifier.sh refuses to deploy from here when this file's
// library does not hash to the one the verifier being deployed compiles.
import {ZKTranscriptLib, RelationsLib} from "../coinbase-attestation/target/CoinbaseAttestation.sol";

/// Deploys one library a generated HonkVerifier links (bb 6.0.0:
/// ZKTranscriptLib and RelationsLib), named by VERIFIER_LIBRARY. Called by
/// scripts/deploy_verifier.sh, which records the address under
/// deployments/<chain>/libraries/<Lib>/<codeHash>.json and reuses it for every
/// verifier with the same library code. The key is read from PRIVATE_KEY in
/// the environment, never from the command line, where a process listing
/// shows it.
contract DeployVerifierLibrary is Script {
    function run() external {
        string memory name = vm.envString("VERIFIER_LIBRARY");
        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        address lib = vm.deployCode(string.concat("CoinbaseAttestation.sol:", name));
        console.log(name, lib);
        vm.stopBroadcast();
    }
}

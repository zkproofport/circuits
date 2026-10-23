// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.21;

import {Script, console} from "forge-std/Script.sol";
import {HonkVerifier} from "../coinbase-attestation-v2/target/CoinbaseAttestationV2.sol";

/// Verifier for coinbase_attestation_v2 (Coinbase KYC v2: revocation bound by
/// an App Attest or AI-server statement). See coinbase-attestation-v2/README.md.
/// deploy_verifier.sh refuses mainnets while the circuit pins the test server key.
contract DeployCoinbaseAttestationV2 is Script {
    function run() external {
        // The key comes from the environment, never the command line, where any
        // process listing shows it (deploy_verifier.sh exports PRIVATE_KEY).
        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        HonkVerifier verifier = new HonkVerifier();
        console.log("CoinbaseAttestationV2 HonkVerifier:", address(verifier));
        vm.stopBroadcast();
    }
}

// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.21;

import {Script, console} from "forge-std/Script.sol";
import {HonkVerifier} from "../coinbase-app-attest-poc/target/CoinbaseAppAttestPoc.sol";

/// PROTOTYPE verifier for coinbase_app_attest_poc (Coinbase KYC v2 with App
/// Attest revocation binding). Testnets only; see coinbase-app-attest-poc/README.md.
contract DeployCoinbaseAppAttestPoc is Script {
    function run() external {
        // The key comes from the environment, never the command line, where any
        // process listing shows it (deploy_verifier.sh exports PRIVATE_KEY).
        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        HonkVerifier verifier = new HonkVerifier();
        console.log("CoinbaseAppAttestPoc HonkVerifier:", address(verifier));
        vm.stopBroadcast();
    }
}

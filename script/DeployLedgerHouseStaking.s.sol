// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {LedgerHouseStaking} from "../src/LedgerHouseStaking.sol";

/// @dev Use Foundry 1.4.3, RPC chain 5042002 and an explicitly supplied signer root.
/// Run without --broadcast first. PRIVATE_KEY is read privately from the environment.
contract DeployLedgerHouseStaking is Script {
    function run() external returns (LedgerHouseStaking staking) {
        require(block.chainid == 5042002, "Ledger House requires Arc testnet");
        bytes32 root = vm.envBytes32("LEDGER_HOUSE_SIGNER_ROOT");
        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        staking = new LedgerHouseStaking(
            0x3600000000000000000000000000000000000000, 0xCbC8E63fF92659E8B44cFF117D33005Bb669a018, root
        );
        vm.stopBroadcast();
        console.log("LedgerHouseStaking:", address(staking));
        console.logBytes32(staking.domainSeparator());
    }
}

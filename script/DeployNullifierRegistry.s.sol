// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.21;

import {Script, console} from "forge-std/Script.sol";
import {NullifierRegistry} from "../src/NullifierRegistry.sol";

contract DeployNullifierRegistry is Script {
    function run() external {
        vm.startBroadcast();
        NullifierRegistry registry = new NullifierRegistry();
        console.log("NullifierRegistry deployed at:", address(registry));
        vm.stopBroadcast();
    }
}

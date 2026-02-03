// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.21;

import {Script, console} from "forge-std/Script.sol";
import {ZKProofPortNullifierRegistry} from "../src/ZKProofPortNullifierRegistry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract DeployZKProofPortNullifierRegistry is Script {
    function run() external {
        vm.startBroadcast();

        // Deploy implementation
        ZKProofPortNullifierRegistry impl = new ZKProofPortNullifierRegistry();
        console.log("Implementation deployed at:", address(impl));

        // Deploy proxy
        bytes memory initData = abi.encodeWithSelector(
            ZKProofPortNullifierRegistry.initialize.selector,
            msg.sender
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        console.log("Proxy (ZKProofPortNullifierRegistry) deployed at:", address(proxy));

        vm.stopBroadcast();
    }
}

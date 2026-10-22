// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.21;

import "forge-std/Test.sol";
import "../src/SnapshotRootRegistry.sol";

contract SnapshotRootRegistryTest is Test {
    SnapshotRootRegistry reg;
    address publisher = address(0xBEEF);

    function setUp() public {
        reg = new SnapshotRootRegistry(publisher, 2);
    }

    function _publish(bytes32 root, uint64 b) internal {
        vm.prank(publisher);
        reg.publish(root, b);
    }

    function test_latest_and_previous_are_accepted_older_is_not() public {
        _publish(bytes32(uint256(1)), 900);
        _publish(bytes32(uint256(2)), 1800);
        _publish(bytes32(uint256(3)), 2700);
        assertTrue(reg.isAcceptedRoot(bytes32(uint256(3))));
        assertTrue(reg.isAcceptedRoot(bytes32(uint256(2))));
        // The root a revoked wallet would still be in, two updates ago.
        assertFalse(reg.isAcceptedRoot(bytes32(uint256(1))));
    }

    function test_unknown_root_is_refused() public {
        _publish(bytes32(uint256(1)), 900);
        assertFalse(reg.isAcceptedRoot(bytes32(uint256(99))));
    }

    function test_window_is_tunable_both_ways() public {
        _publish(bytes32(uint256(1)), 900);
        _publish(bytes32(uint256(2)), 1800);
        reg.setAcceptedRoots(1);
        assertFalse(reg.isAcceptedRoot(bytes32(uint256(1))));
        reg.setAcceptedRoots(3);
        assertTrue(reg.isAcceptedRoot(bytes32(uint256(1))));
    }

    function test_only_publisher_publishes() public {
        vm.expectRevert(SnapshotRootRegistry.NotPublisher.selector);
        reg.publish(bytes32(uint256(1)), 900);
    }

    function test_only_owner_tunes() public {
        vm.prank(address(0xBAD));
        vm.expectRevert(SnapshotRootRegistry.NotOwner.selector);
        reg.setAcceptedRoots(5);
    }

    function test_blocks_must_advance() public {
        _publish(bytes32(uint256(1)), 1800);
        vm.prank(publisher);
        vm.expectRevert(abi.encodeWithSelector(SnapshotRootRegistry.BlockNotAfterLatest.selector, uint64(1800), uint64(900)));
        reg.publish(bytes32(uint256(2)), 900);
    }

    function test_a_set_that_comes_back_is_current_again() public {
        // {x} -> {x, y} -> y revoked -> {x} again. Refusing the repeat would
        // leave {x, y}, which still holds the revoked y, as the latest root.
        _publish(bytes32(uint256(1)), 900);
        _publish(bytes32(uint256(2)), 1800);
        _publish(bytes32(uint256(3)), 2700);
        _publish(bytes32(uint256(1)), 3600);
        assertTrue(reg.isAcceptedRoot(bytes32(uint256(1))));
        assertTrue(reg.isAcceptedRoot(bytes32(uint256(3))));
        assertFalse(reg.isAcceptedRoot(bytes32(uint256(2))));
    }

    function test_zero_window_and_zero_root_are_refused() public {
        vm.expectRevert(abi.encodeWithSelector(SnapshotRootRegistry.AcceptedRootsOutOfRange.selector, uint8(0)));
        reg.setAcceptedRoots(0);
        vm.prank(publisher);
        vm.expectRevert(SnapshotRootRegistry.ZeroRoot.selector);
        reg.publish(bytes32(0), 900);
    }

    function test_publish_gas() public {
        _publish(bytes32(uint256(1)), 900);
        vm.prank(publisher);
        uint256 g = gasleft();
        reg.publish(bytes32(uint256(2)), 1800);
        emit log_named_uint("publish gas (steady state, excl. 21k base)", g - gasleft());
    }
}

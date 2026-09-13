// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {LedgerHouseStaking, IArcEligibilityVerifier} from "../src/LedgerHouseStaking.sol";

contract LedgerHouseTestToken is ERC20 {
    uint8 public mode;
    address public callbackTarget;
    bytes public callback;
    constructor() ERC20("Test USDC", "USDC") {}

    function decimals() public pure override returns (uint8) {
        return 6;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function burn(address from, uint256 amount) external {
        _burn(from, amount);
    }

    function setMode(uint8 value) external {
        mode = value;
    }

    function setCallback(address target, bytes memory data) external {
        callbackTarget = target;
        callback = data;
    }

    function _callback() private {
        if (callbackTarget != address(0)) {
            (bool ok, bytes memory reason) = callbackTarget.call(callback);
            if (!ok) assembly { revert(add(reason, 32), mload(reason)) }
        }
    }

    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        if (mode == 1) return false;
        require(mode != 2, "token unavailable");
        _callback();
        if (mode == 3) return super.transferFrom(from, to, amount - 1);
        return super.transferFrom(from, to, amount);
    }

    function transfer(address to, uint256 amount) public override returns (bool) {
        if (mode == 1) return false;
        require(mode != 2, "token unavailable");
        _callback();
        return super.transfer(to, amount);
    }
}

contract LedgerHouseTestVerifier is IArcEligibilityVerifier {
    bool public accepted = true;
    bool public unavailable;

    function setAccepted(bool value) external {
        accepted = value;
    }

    function setUnavailable() external {
        unavailable = true;
    }

    function verify(bytes calldata, bytes32[] calldata) external view returns (bool) {
        require(!unavailable, "verifier unavailable");
        return accepted;
    }
}

contract LedgerHouseStakingTest is Test {
    LedgerHouseStaking internal staking;
    LedgerHouseTestToken internal token;
    LedgerHouseTestVerifier internal verifier;
    address internal delegate = address(0xB);
    address internal thief = address(0xC);
    bytes32 internal constant ROOT = keccak256("trusted signer root");
    uint256 internal constant AMOUNT = 1_000_000;
    uint256 internal constant EXPIRY = 2000;
    bytes internal proof = hex"010203";

    function setUp() public {
        vm.chainId(5042002);
        vm.warp(1000);
        token = new LedgerHouseTestToken();
        verifier = new LedgerHouseTestVerifier();
        staking = new LedgerHouseStaking(address(token), address(verifier), ROOT);
        token.mint(delegate, 10 * AMOUNT);
        vm.prank(delegate);
        token.approve(address(staking), type(uint256).max);
    }

    function _put(bytes32[] memory inputs, uint256 offset, bytes32 hash) internal pure {
        for (uint256 i; i < 32; ++i) {
            inputs[offset + i] = bytes32(uint256(uint8(hash[i])));
        }
    }

    function _inputs(address wallet, uint256 amount, uint256 expiry, string memory nonce)
        internal
        view
        returns (bytes32[] memory inputs)
    {
        inputs = new bytes32[](192);
        _put(inputs, 0, keccak256("signal"));
        _put(inputs, 32, staking.domainSeparator());
        _put(inputs, 64, staking.actionHash(wallet, amount, expiry, nonce));
        _put(inputs, 96, ROOT);
        _put(inputs, 128, keccak256("ledger-house"));
        _put(inputs, 160, keccak256("credential nullifier"));
    }

    function _stake(uint256 amount, string memory nonce) internal {
        bytes32[] memory inputs = _inputs(delegate, amount, EXPIRY, nonce);
        vm.prank(delegate);
        staking.stake(amount, proof, inputs, EXPIRY, nonce);
    }

    function _reject(bytes32[] memory inputs, bytes4 selector) internal {
        vm.prank(delegate);
        vm.expectRevert(selector);
        staking.stake(AMOUNT, proof, inputs, EXPIRY, "one");
    }

    function testStakeTransfersTokensAndEmitsAction() public {
        bytes32[] memory inputs = _inputs(delegate, AMOUNT, EXPIRY, "one");
        vm.expectCall(address(verifier), abi.encodeCall(IArcEligibilityVerifier.verify, (proof, inputs)));
        vm.expectEmit(true, true, false, true, address(staking));
        emit LedgerHouseStaking.Staked(delegate, AMOUNT, staking.actionHash(delegate, AMOUNT, EXPIRY, "one"));
        _stake(AMOUNT, "one");
        assertEq(staking.balances(delegate), AMOUNT);
        assertEq(token.balanceOf(address(staking)), AMOUNT);
        assertEq(token.balanceOf(delegate), 9 * AMOUNT);
        assertTrue(staking.usedNonces(delegate, keccak256("one")));
        assertTrue(staking.usedActions(staking.actionHash(delegate, AMOUNT, EXPIRY, "one")));
    }

    function testActionHashMatchesEthersTypedDataEncoderVector() public view {
        // Independent ethers TypedDataEncoder.hashStruct fixture; fixes field order and token units.
        assertEq(
            staking.actionHash(delegate, AMOUNT, EXPIRY, "one"),
            0x276dd86c99bafbdc05dac35ea0d9239d061e15f85213717646ebf0eae5d123ca
        );
    }

    function testRejectForgedSignerRoot() public {
        bytes32[] memory inputs = _inputs(delegate, AMOUNT, EXPIRY, "one");
        _put(inputs, 96, keccak256("attacker root"));
        _reject(inputs, LedgerHouseStaking.SignerRootMismatch.selector);
    }

    function testRejectWrongScope() public {
        bytes32[] memory inputs = _inputs(delegate, AMOUNT, EXPIRY, "one");
        _put(inputs, 128, keccak256("other service"));
        _reject(inputs, LedgerHouseStaking.ScopeMismatch.selector);
    }

    function testRejectWrongDomainAndContract() public {
        LedgerHouseStaking other = new LedgerHouseStaking(address(token), address(verifier), ROOT);
        bytes32[] memory inputs = _inputs(delegate, AMOUNT, EXPIRY, "one");
        _put(inputs, 32, other.domainSeparator());
        _reject(inputs, LedgerHouseStaking.DomainMismatch.selector);
    }

    function testRejectWrongSender() public {
        bytes32[] memory inputs = _inputs(delegate, AMOUNT, EXPIRY, "one");
        vm.prank(thief);
        vm.expectRevert(LedgerHouseStaking.ActionMismatch.selector);
        staking.stake(AMOUNT, proof, inputs, EXPIRY, "one");
    }

    function testRejectWrongAmount() public {
        _reject(_inputs(delegate, AMOUNT + 1, EXPIRY, "one"), LedgerHouseStaking.ActionMismatch.selector);
    }

    function testRejectWrongNonce() public {
        _reject(_inputs(delegate, AMOUNT, EXPIRY, "two"), LedgerHouseStaking.ActionMismatch.selector);
    }

    function testRejectWrongExpiry() public {
        _reject(_inputs(delegate, AMOUNT, EXPIRY + 1, "one"), LedgerHouseStaking.ActionMismatch.selector);
    }

    function testRejectWrongAction() public {
        bytes32[] memory inputs = _inputs(delegate, AMOUNT, EXPIRY, "one");
        _put(
            inputs,
            64,
            keccak256(
                abi.encode(
                    staking.DELEGATION_TYPEHASH(), delegate, keccak256("withdraw"), AMOUNT, EXPIRY, keccak256("one")
                )
            )
        );
        _reject(inputs, LedgerHouseStaking.ActionMismatch.selector);
    }

    function testRejectReplayAfterWithdrawal() public {
        _stake(AMOUNT, "one");
        vm.prank(delegate);
        staking.withdraw(AMOUNT);
        _reject(_inputs(delegate, AMOUNT, EXPIRY, "one"), LedgerHouseStaking.DelegationUsed.selector);
    }

    function testRejectNonceReuseWithNewAmount() public {
        _stake(1, "one");
        _reject(_inputs(delegate, AMOUNT, EXPIRY, "one"), LedgerHouseStaking.DelegationUsed.selector);
    }

    function testRepeatedCredentialWithFreshDelegation() public {
        _stake(AMOUNT, "one");
        _stake(AMOUNT, "two");
        assertEq(staking.balances(delegate), 2 * AMOUNT);
    }

    function testNonceIsScopedToSender() public {
        _stake(AMOUNT, "one");
        bytes32[] memory inputs = _inputs(thief, AMOUNT, EXPIRY, "one");
        token.mint(thief, AMOUNT);
        vm.startPrank(thief);
        token.approve(address(staking), AMOUNT);
        staking.stake(AMOUNT, proof, inputs, EXPIRY, "one");
        vm.stopPrank();
        assertEq(staking.balances(thief), AMOUNT);
    }

    function testRejectZeroAmount() public {
        bytes32[] memory inputs = _inputs(delegate, 0, EXPIRY, "one");
        vm.expectRevert(LedgerHouseStaking.InvalidAmount.selector);
        staking.stake(0, proof, inputs, EXPIRY, "one");
    }

    function testStakeOneUnit() public {
        _stake(1, "one");
        assertEq(staking.balances(delegate), 1);
    }

    function testStakeMaximumAmount() public {
        token.burn(delegate, token.balanceOf(delegate));
        token.mint(delegate, type(uint256).max);
        _stake(type(uint256).max, "max");
        assertEq(staking.balances(delegate), type(uint256).max);
        vm.prank(delegate);
        staking.withdraw(type(uint256).max);
        assertEq(token.balanceOf(delegate), type(uint256).max);
    }

    function testPackedStakeParity() public {
        bytes32[] memory inputs = _inputs(delegate, AMOUNT, EXPIRY, "one");
        vm.expectCall(address(verifier), abi.encodeCall(IArcEligibilityVerifier.verify, (proof, inputs)));
        vm.prank(delegate);
        staking.stakePacked(AMOUNT, proof, abi.encodePacked(inputs), EXPIRY, "one");
        assertEq(staking.balances(delegate), AMOUNT);
        assertEq(token.balanceOf(address(staking)), AMOUNT);
        _reject(inputs, LedgerHouseStaking.DelegationUsed.selector);
    }

    function testPackedRejectInvalidLength() public {
        uint256[4] memory lengths = [uint256(0), 192, 6143, 6145];
        for (uint256 i; i < lengths.length; ++i) {
            vm.prank(delegate);
            vm.expectRevert(LedgerHouseStaking.InvalidPublicInputLength.selector);
            staking.stakePacked(AMOUNT, proof, new bytes(lengths[i]), EXPIRY, "one");
        }
    }

    function testPackedRejectForgedRoot() public {
        bytes32[] memory inputs = _inputs(delegate, AMOUNT, EXPIRY, "one");
        _put(inputs, 96, keccak256("attacker root"));
        vm.prank(delegate);
        vm.expectRevert(LedgerHouseStaking.SignerRootMismatch.selector);
        staking.stakePacked(AMOUNT, proof, abi.encodePacked(inputs), EXPIRY, "one");
    }

    function testRejectExpiredAndExactDeadline() public {
        for (uint256 expiry = 999; expiry <= 1000; ++expiry) {
            bytes32[] memory inputs = _inputs(delegate, AMOUNT, expiry, "one");
            vm.prank(delegate);
            vm.expectRevert(LedgerHouseStaking.ExpiredDelegation.selector);
            staking.stake(AMOUNT, proof, inputs, expiry, "one");
        }
    }

    function testAcceptOneSecondBeforeDeadline() public {
        vm.warp(EXPIRY - 1);
        _stake(AMOUNT, "one");
    }

    function testRejectEmptyAndOversizedNonce() public {
        string[2] memory nonces = [string(""), string(new bytes(129))];
        for (uint256 i; i < nonces.length; ++i) {
            bytes32[] memory inputs = _inputs(delegate, AMOUNT, EXPIRY, nonces[i]);
            vm.prank(delegate);
            vm.expectRevert(LedgerHouseStaking.InvalidNonce.selector);
            staking.stake(AMOUNT, proof, inputs, EXPIRY, nonces[i]);
        }
    }

    function testNonceMaximumAndOpaqueCharacters() public {
        _stake(1, string(new bytes(128)));
        _stake(1, " \t\n");
        _stake(1, unicode"한국어🔐mix\n\t");
        _stake(1, "%_\\' OR 1=1;<script>\x00");
        assertEq(staking.balances(delegate), 4);
    }

    function testRejectEmptyAndOversizedProof() public {
        bytes32[] memory inputs = _inputs(delegate, AMOUNT, EXPIRY, "one");
        for (uint256 i; i < 2; ++i) {
            bytes memory invalidProof = new bytes(i * 65537);
            vm.prank(delegate);
            vm.expectRevert(LedgerHouseStaking.InvalidProofLength.selector);
            staking.stake(AMOUNT, invalidProof, inputs, EXPIRY, "one");
        }
    }

    function testRejectMissingAndExtraFields() public {
        _reject(new bytes32[](191), LedgerHouseStaking.InvalidPublicInputLength.selector);
        _reject(new bytes32[](193), LedgerHouseStaking.InvalidPublicInputLength.selector);
    }

    function testFuzzRejectNonByteField(uint8 index, uint256 value) public {
        uint256 offset = bound(index, 0, 191);
        value = bound(value, 256, type(uint256).max);
        bytes32[] memory inputs = _inputs(delegate, AMOUNT, EXPIRY, "one");
        inputs[offset] = bytes32(value);
        vm.prank(delegate);
        vm.expectRevert(abi.encodeWithSelector(LedgerHouseStaking.InvalidByteField.selector, offset));
        staking.stake(AMOUNT, proof, inputs, EXPIRY, "one");
    }

    function testRejectFalseVerifier() public {
        verifier.setAccepted(false);
        _reject(_inputs(delegate, AMOUNT, EXPIRY, "one"), LedgerHouseStaking.InvalidProof.selector);
        assertEq(staking.balances(delegate), 0);
    }

    function testVerifierFailureIsAtomic() public {
        verifier.setUnavailable();
        bytes32[] memory inputs = _inputs(delegate, AMOUNT, EXPIRY, "one");
        vm.prank(delegate);
        vm.expectRevert("verifier unavailable");
        staking.stake(AMOUNT, proof, inputs, EXPIRY, "one");
        assertFalse(staking.usedNonces(delegate, keccak256("one")));
    }

    function testTokenFailureRollsBackNonceAndBalance() public {
        token.setMode(1);
        bytes32[] memory inputs = _inputs(delegate, AMOUNT, EXPIRY, "one");
        vm.prank(delegate);
        vm.expectRevert(abi.encodeWithSelector(SafeERC20.SafeERC20FailedOperation.selector, address(token)));
        staking.stake(AMOUNT, proof, inputs, EXPIRY, "one");
        assertEq(staking.balances(delegate), 0);
        assertFalse(staking.usedNonces(delegate, keccak256("one")));
        assertFalse(staking.usedActions(staking.actionHash(delegate, AMOUNT, EXPIRY, "one")));
        token.setMode(0);
        _stake(AMOUNT, "one");
    }

    function testTokenRevertIsAtomic() public {
        token.setMode(2);
        bytes32[] memory inputs = _inputs(delegate, AMOUNT, EXPIRY, "one");
        vm.prank(delegate);
        vm.expectRevert("token unavailable");
        staking.stake(AMOUNT, proof, inputs, EXPIRY, "one");
        assertEq(staking.balances(delegate), 0);
    }

    function testRejectFeeOnTransfer() public {
        token.setMode(3);
        _reject(_inputs(delegate, AMOUNT, EXPIRY, "one"), LedgerHouseStaking.TransferAmountMismatch.selector);
        assertEq(staking.balances(delegate), 0);
        assertEq(token.balanceOf(address(staking)), 0);
    }

    function testInsufficientAllowanceDoesNotConsumeProof() public {
        vm.prank(delegate);
        token.approve(address(staking), 0);
        bytes32[] memory inputs = _inputs(delegate, AMOUNT, EXPIRY, "one");
        vm.prank(delegate);
        vm.expectRevert();
        staking.stake(AMOUNT, proof, inputs, EXPIRY, "one");
        assertFalse(staking.usedNonces(delegate, keccak256("one")));
    }

    function testWithdrawPartialAndFullToOwner() public {
        _stake(AMOUNT, "one");
        vm.startPrank(delegate);
        staking.withdraw(1);
        assertEq(staking.balances(delegate), AMOUNT - 1);
        staking.withdraw(AMOUNT - 1);
        vm.stopPrank();
        assertEq(staking.balances(delegate), 0);
        assertEq(token.balanceOf(delegate), 10 * AMOUNT);
    }

    function testRejectUnauthorizedZeroAndExcessWithdrawal() public {
        _stake(AMOUNT, "one");
        vm.prank(thief);
        vm.expectRevert(LedgerHouseStaking.InsufficientStake.selector);
        staking.withdraw(1);
        vm.startPrank(delegate);
        vm.expectRevert(LedgerHouseStaking.InvalidAmount.selector);
        staking.withdraw(0);
        vm.expectRevert(LedgerHouseStaking.InsufficientStake.selector);
        staking.withdraw(AMOUNT + 1);
        vm.stopPrank();
    }

    function testWithdrawalTransferFailureRestoresBalance() public {
        _stake(AMOUNT, "one");
        token.setMode(1);
        vm.prank(delegate);
        vm.expectRevert(abi.encodeWithSelector(SafeERC20.SafeERC20FailedOperation.selector, address(token)));
        staking.withdraw(AMOUNT);
        assertEq(staking.balances(delegate), AMOUNT);
    }

    function testRejectStakeReentrancy() public {
        bytes32[] memory inputs = _inputs(delegate, AMOUNT, EXPIRY, "one");
        token.setCallback(address(staking), abi.encodeCall(staking.stake, (AMOUNT, proof, inputs, EXPIRY, "one")));
        _reject(inputs, ReentrancyGuard.ReentrancyGuardReentrantCall.selector);
        assertEq(staking.balances(delegate), 0);
    }

    function testRejectWithdrawReentrancy() public {
        _stake(AMOUNT, "one");
        token.setCallback(address(staking), abi.encodeCall(staking.withdraw, (1)));
        vm.prank(delegate);
        vm.expectRevert(ReentrancyGuard.ReentrancyGuardReentrantCall.selector);
        staking.withdraw(AMOUNT);
        assertEq(staking.balances(delegate), AMOUNT);
    }

    function testRejectWrongChainOnStakeAndDeployment() public {
        bytes32[] memory inputs = _inputs(delegate, AMOUNT, EXPIRY, "one");
        vm.chainId(1);
        _reject(inputs, LedgerHouseStaking.WrongChain.selector);
        vm.expectRevert(LedgerHouseStaking.WrongChain.selector);
        new LedgerHouseStaking(address(token), address(verifier), ROOT);
    }

    function testRejectInvalidConstructorConfiguration() public {
        vm.expectRevert(LedgerHouseStaking.InvalidConfiguration.selector);
        new LedgerHouseStaking(address(0), address(verifier), ROOT);
        vm.expectRevert(LedgerHouseStaking.InvalidConfiguration.selector);
        new LedgerHouseStaking(address(token), address(0), ROOT);
        vm.expectRevert(LedgerHouseStaking.InvalidConfiguration.selector);
        new LedgerHouseStaking(address(token), address(verifier), bytes32(0));
    }
}

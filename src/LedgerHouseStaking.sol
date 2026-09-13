// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

interface IArcEligibilityVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool);
}

/// @notice Arc testnet USDC custody demo, authorized by action-bound KYC proofs.
/// @dev No yield or admin withdrawal. Amounts use the token's six decimal units.
contract LedgerHouseStaking is ReentrancyGuard {
    using SafeERC20 for IERC20;

    uint256 public constant CHAIN_ID = 5042002;
    uint256 public constant MAX_NONCE_BYTES = 128;
    uint256 public constant MAX_PROOF_BYTES = 65536;
    bytes32 public constant SCOPE = keccak256("ledger-house");
    bytes32 public constant DELEGATION_TYPEHASH =
        keccak256("CredentialDelegation(address delegate,string action,uint256 amount,uint256 expiresAt,string nonce)");
    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    IERC20 public immutable usdc;
    IArcEligibilityVerifier public immutable verifier;
    bytes32 public immutable trustedSignerRoot;
    mapping(address => uint256) public balances;
    mapping(address => mapping(bytes32 => bool)) public usedNonces;
    mapping(bytes32 => bool) public usedActions;

    error WrongChain();
    error InvalidConfiguration();
    error InvalidAmount();
    error InvalidNonce();
    error InvalidProofLength();
    error ExpiredDelegation();
    error InvalidPublicInputLength();
    error InvalidByteField(uint256 index);
    error DomainMismatch();
    error ActionMismatch();
    error SignerRootMismatch();
    error ScopeMismatch();
    error DelegationUsed();
    error InvalidProof();
    error TransferAmountMismatch();
    error InsufficientStake();

    event Staked(address indexed delegate, uint256 amount, bytes32 indexed actionHash);
    event Withdrawn(address indexed delegate, uint256 amount);

    constructor(address usdc_, address verifier_, bytes32 trustedSignerRoot_) {
        if (block.chainid != CHAIN_ID) revert WrongChain();
        if (usdc_.code.length == 0 || verifier_.code.length == 0 || trustedSignerRoot_ == bytes32(0)) {
            revert InvalidConfiguration();
        }
        if (IERC20Metadata(usdc_).decimals() != 6) revert InvalidConfiguration();
        usdc = IERC20(usdc_);
        verifier = IArcEligibilityVerifier(verifier_);
        trustedSignerRoot = trustedSignerRoot_;
    }

    function domainSeparator() public view returns (bytes32) {
        return keccak256(
            abi.encode(DOMAIN_TYPEHASH, keccak256("Ledger House Staking"), keccak256("1"), block.chainid, address(this))
        );
    }

    /// @notice EIP-712 struct hash, without the domain or 0x1901 prefix.
    function actionHash(address delegate, uint256 amount, uint256 expiresAt, string memory nonce)
        public
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(DELEGATION_TYPEHASH, delegate, keccak256("stake"), amount, expiresAt, keccak256(bytes(nonce)))
        );
    }

    function stake(
        uint256 amount,
        bytes calldata proof,
        bytes32[] calldata publicInputs,
        uint256 expiresAt,
        string calldata nonce
    ) external nonReentrant {
        _stake(amount, proof, publicInputs, expiresAt, nonce);
    }

    /// @notice Circle CLI adapter: 192 concatenated bytes32 words, without an ABI array header.
    function stakePacked(
        uint256 amount,
        bytes calldata proof,
        bytes calldata packedPublicInputs,
        uint256 expiresAt,
        string calldata nonce
    ) external nonReentrant {
        if (packedPublicInputs.length != 192 * 32) revert InvalidPublicInputLength();
        bytes32[] memory inputs = new bytes32[](192);
        for (uint256 i; i < 192; ++i) {
            inputs[i] = bytes32(packedPublicInputs[i * 32:(i + 1) * 32]);
        }
        _stake(amount, proof, inputs, expiresAt, nonce);
    }

    function _stake(
        uint256 amount,
        bytes calldata proof,
        bytes32[] memory publicInputs,
        uint256 expiresAt,
        string calldata nonce
    ) private {
        if (block.chainid != CHAIN_ID) revert WrongChain();
        if (amount == 0) revert InvalidAmount();
        if (expiresAt <= block.timestamp) revert ExpiredDelegation();
        if (bytes(nonce).length == 0 || bytes(nonce).length > MAX_NONCE_BYTES) revert InvalidNonce();
        if (proof.length == 0 || proof.length > MAX_PROOF_BYTES) revert InvalidProofLength();
        if (publicInputs.length != 192) revert InvalidPublicInputLength();
        // Noir exposes six [u8;32] values as 192 individual field elements.
        // Validate even the opaque signal/nullifier bytes before calling the verifier.
        for (uint256 i; i < 192; ++i) {
            if (uint256(publicInputs[i]) > 255) revert InvalidByteField(i);
        }
        if (_readHash(publicInputs, 32) != domainSeparator()) revert DomainMismatch();
        bytes32 hash = actionHash(msg.sender, amount, expiresAt, nonce);
        if (_readHash(publicInputs, 64) != hash) revert ActionMismatch();
        if (_readHash(publicInputs, 96) != trustedSignerRoot) revert SignerRootMismatch();
        if (_readHash(publicInputs, 128) != SCOPE) revert ScopeMismatch();
        bytes32 nonceHash = keccak256(bytes(nonce));
        if (usedNonces[msg.sender][nonceHash] || usedActions[hash]) revert DelegationUsed();
        if (!verifier.verify(proof, publicInputs)) revert InvalidProof();

        usedNonces[msg.sender][nonceHash] = true;
        usedActions[hash] = true;
        balances[msg.sender] += amount;
        uint256 beforeBalance = usdc.balanceOf(address(this));
        usdc.safeTransferFrom(msg.sender, address(this), amount);
        if (usdc.balanceOf(address(this)) - beforeBalance != amount) revert TransferAmountMismatch();
        emit Staked(msg.sender, amount, hash);
    }

    function withdraw(uint256 amount) external nonReentrant {
        if (amount == 0) revert InvalidAmount();
        if (amount > balances[msg.sender]) revert InsufficientStake();
        balances[msg.sender] -= amount;
        usdc.safeTransfer(msg.sender, amount);
        emit Withdrawn(msg.sender, amount);
    }

    function _readHash(bytes32[] memory fields, uint256 offset) private pure returns (bytes32) {
        uint256 result;
        for (uint256 i; i < 32; ++i) {
            result = (result << 8) | uint256(fields[offset + i]);
        }
        return bytes32(result);
    }
}

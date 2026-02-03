// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.21;

import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

contract ZKProofPortNullifierRegistry is UUPSUpgradeable, OwnableUpgradeable {

    enum VerifyStatus {
        VERIFIED_AND_REGISTERED,
        ALREADY_REGISTERED,
        EXPIRED_AND_REREGISTERED,
        VERIFICATION_FAILED,
        CIRCUIT_NOT_FOUND
    }

    struct CircuitConfig {
        address verifier;
        uint256 scopeIndex;
        uint256 nullifierIndex;
        bool active;
    }

    struct NullifierRecord {
        uint64 registeredAt;
        bytes32 scope;
        bytes32 circuitId;
    }

    mapping(bytes32 => CircuitConfig) public circuits;
    mapping(bytes32 => NullifierRecord) public nullifiers;
    mapping(bytes32 => uint64) public circuitTTL;
    mapping(address => bool) public authorizedRelayers;

    event CircuitRegistered(bytes32 indexed circuitId, address verifier);
    event NullifierRegistered(bytes32 indexed nullifier, bytes32 indexed scope, bytes32 indexed circuitId);
    event RelayerAdded(address indexed relayer);
    event RelayerRemoved(address indexed relayer);
    event CircuitTTLUpdated(bytes32 indexed circuitId, uint64 ttlSeconds);

    error OnlyRelayer();

    modifier onlyRelayer() {
        if (!authorizedRelayers[msg.sender]) revert OnlyRelayer();
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address initialOwner) external initializer {
        __Ownable_init(initialOwner);
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}

    // === ADMIN ===

    function registerCircuit(
        bytes32 _circuitId,
        address _verifier,
        uint256 _scopeIndex,
        uint256 _nullifierIndex
    ) external onlyOwner {
        circuits[_circuitId] = CircuitConfig(_verifier, _scopeIndex, _nullifierIndex, true);
        emit CircuitRegistered(_circuitId, _verifier);
    }

    function setCircuitTTL(bytes32 _circuitId, uint64 _ttlSeconds) external onlyOwner {
        circuitTTL[_circuitId] = _ttlSeconds;
        emit CircuitTTLUpdated(_circuitId, _ttlSeconds);
    }

    function addRelayer(address _relayer) external onlyOwner {
        authorizedRelayers[_relayer] = true;
        emit RelayerAdded(_relayer);
    }

    function removeRelayer(address _relayer) external onlyOwner {
        authorizedRelayers[_relayer] = false;
        emit RelayerRemoved(_relayer);
    }

    // === RELAYER-ONLY (Plan 2) ===

    function verifyAndRegister(
        bytes32 _circuitId,
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external onlyRelayer returns (VerifyStatus status, bytes32 nullifier, bytes32 scope) {
        CircuitConfig memory config = circuits[_circuitId];
        if (!config.active) {
            return (VerifyStatus.CIRCUIT_NOT_FOUND, bytes32(0), bytes32(0));
        }

        nullifier = _reconstructBytes32FromFields(_publicInputs, config.nullifierIndex);

        NullifierRecord storage record = nullifiers[nullifier];
        if (record.registeredAt > 0) {
            uint64 ttl = circuitTTL[_circuitId];
            if (ttl == 0 || block.timestamp <= record.registeredAt + ttl) {
                return (VerifyStatus.ALREADY_REGISTERED, nullifier, record.scope);
            }
            // Expired — fall through to re-verify
        }

        (bool success, bytes memory result) = config.verifier.staticcall(
            abi.encodeWithSignature("verify(bytes,bytes32[])", _proof, _publicInputs)
        );
        if (!success || !abi.decode(result, (bool))) {
            return (VerifyStatus.VERIFICATION_FAILED, nullifier, bytes32(0));
        }

        scope = _reconstructBytes32FromFields(_publicInputs, config.scopeIndex);

        bool wasExpired = record.registeredAt > 0;
        record.registeredAt = uint64(block.timestamp);
        record.scope = scope;
        record.circuitId = _circuitId;

        emit NullifierRegistered(nullifier, scope, _circuitId);

        return (
            wasExpired ? VerifyStatus.EXPIRED_AND_REREGISTERED : VerifyStatus.VERIFIED_AND_REGISTERED,
            nullifier,
            scope
        );
    }

    // === PUBLIC VIEW ===

    function isNullifierRegistered(bytes32 _nullifier) external view returns (bool) {
        return nullifiers[_nullifier].registeredAt > 0;
    }

    function getNullifierInfo(bytes32 _nullifier)
        external view returns (uint64 registeredAt, bytes32 scope, bytes32 circuitId)
    {
        NullifierRecord storage record = nullifiers[_nullifier];
        return (record.registeredAt, record.scope, record.circuitId);
    }

    function verifyOnly(
        bytes32 _circuitId,
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external view returns (bool) {
        CircuitConfig memory config = circuits[_circuitId];
        if (!config.active) return false;
        (bool success, bytes memory result) = config.verifier.staticcall(
            abi.encodeWithSignature("verify(bytes,bytes32[])", _proof, _publicInputs)
        );
        return success && abi.decode(result, (bool));
    }

    // === INTERNAL ===

    function _reconstructBytes32FromFields(
        bytes32[] calldata _publicInputs,
        uint256 startIndex
    ) internal pure returns (bytes32) {
        bytes memory result = new bytes(32);
        for (uint256 i = 0; i < 32; i++) {
            result[i] = bytes1(uint8(uint256(_publicInputs[startIndex + i])));
        }
        return bytes32(result);
    }
}

// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.21;

contract NullifierRegistry {
    address public owner;

    struct CircuitConfig {
        address verifier;
        uint256 scopeIndex;
        uint256 nullifierIndex;
        bool active;
    }

    mapping(bytes32 => CircuitConfig) public circuits;
    mapping(bytes32 => bool) public nullifierUsed;
    mapping(bytes32 => bytes32) public nullifierScope;
    mapping(bytes32 => bytes32) public nullifierCircuit;

    event CircuitRegistered(bytes32 indexed circuitId, address verifier);
    event CircuitUpdated(bytes32 indexed circuitId, address newVerifier);
    event NullifierRegistered(bytes32 indexed nullifier, bytes32 indexed scope, bytes32 indexed circuitId);

    error NullifierAlreadyUsed(bytes32 nullifier);
    error CircuitNotRegistered(bytes32 circuitId);
    error ProofVerificationFailed();
    error OnlyOwner();

    modifier onlyOwner() {
        if (msg.sender != owner) revert OnlyOwner();
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function registerCircuit(
        bytes32 _circuitId,
        address _verifier,
        uint256 _scopeIndex,
        uint256 _nullifierIndex
    ) external onlyOwner {
        circuits[_circuitId] = CircuitConfig(_verifier, _scopeIndex, _nullifierIndex, true);
        emit CircuitRegistered(_circuitId, _verifier);
    }

    function updateCircuit(
        bytes32 _circuitId,
        address _newVerifier,
        uint256 _scopeIndex,
        uint256 _nullifierIndex
    ) external onlyOwner {
        if (!circuits[_circuitId].active) revert CircuitNotRegistered(_circuitId);
        circuits[_circuitId].verifier = _newVerifier;
        circuits[_circuitId].scopeIndex = _scopeIndex;
        circuits[_circuitId].nullifierIndex = _nullifierIndex;
        emit CircuitUpdated(_circuitId, _newVerifier);
    }

    function verifyAndRegister(
        bytes32 _circuitId,
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external returns (bool) {
        CircuitConfig memory config = circuits[_circuitId];
        if (!config.active) revert CircuitNotRegistered(_circuitId);

        bytes32 nullifier = reconstructBytes32FromFields(_publicInputs, config.nullifierIndex);
        if (nullifierUsed[nullifier]) revert NullifierAlreadyUsed(nullifier);

        (bool success, bytes memory result) = config.verifier.staticcall(
            abi.encodeWithSignature("verify(bytes,bytes32[])", _proof, _publicInputs)
        );
        if (!success || !abi.decode(result, (bool))) revert ProofVerificationFailed();

        bytes32 scope = reconstructBytes32FromFields(_publicInputs, config.scopeIndex);
        nullifierUsed[nullifier] = true;
        nullifierScope[nullifier] = scope;
        nullifierCircuit[nullifier] = _circuitId;

        emit NullifierRegistered(nullifier, scope, _circuitId);
        return true;
    }

    function reconstructBytes32FromFields(
        bytes32[] calldata _publicInputs,
        uint256 startIndex
    ) internal pure returns (bytes32) {
        bytes memory result = new bytes(32);
        for (uint256 i = 0; i < 32; i++) {
            result[i] = bytes1(uint8(uint256(_publicInputs[startIndex + i])));
        }
        return bytes32(result);
    }

    function isNullifierUsed(bytes32 _nullifier) external view returns (bool) {
        return nullifierUsed[_nullifier];
    }

    function getScope(bytes32 _nullifier) external view returns (bytes32) {
        return nullifierScope[_nullifier];
    }

    function getCircuit(bytes32 _nullifier) external view returns (bytes32) {
        return nullifierCircuit[_nullifier];
    }

    function verifyOnly(
        bytes32 _circuitId,
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external view returns (bool) {
        CircuitConfig memory config = circuits[_circuitId];
        if (!config.active) revert CircuitNotRegistered(_circuitId);
        (bool success, bytes memory result) = config.verifier.staticcall(
            abi.encodeWithSignature("verify(bytes,bytes32[])", _proof, _publicInputs)
        );
        return success && abi.decode(result, (bool));
    }
}

// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

struct AttestationRequestData {
    address recipient;
    uint64 expirationTime;
    bool revocable;
    bytes32 refUID;
    bytes data;
    uint256 value;
}

struct AttestationRequest {
    bytes32 schema;
    AttestationRequestData data;
}

interface IEAS {
    function attest(AttestationRequest calldata request) external payable returns (bytes32);
}

/// @title MockCoinbaseAttester (GIWA PoC)
/// @notice Mimics Coinbase StaticAttester.attestAccount(address) for GIWA Sepolia.
///         Function selector 0x56feed5e MUST match the Noir circuit's ATTEST_ACCOUNT_SELECTOR.
///         Internally wraps GIWA's EAS predeploy to register a 'bool verifiedAccount' attestation.
contract MockCoinbaseAttester {
    IEAS private constant _EAS = IEAS(0x4200000000000000000000000000000000000021);

    bytes32 public immutable verifiedAccountSchema;
    address public immutable attester;

    error InvalidRecipient();
    error NotAttester();

    event AttestationCreated(address indexed recipient, bytes32 attestationUid);

    constructor(bytes32 _verifiedAccountSchema, address _attester) {
        require(_verifiedAccountSchema != bytes32(0), "schema 0");
        require(_attester != address(0), "attester 0");
        verifiedAccountSchema = _verifiedAccountSchema;
        attester = _attester;
    }

    /// @notice Selector 0x56feed5e — must match Noir circuit ATTEST_ACCOUNT_SELECTOR.
    function attestAccount(address recipient) external returns (bytes32) {
        if (msg.sender != attester) revert NotAttester();
        if (recipient == address(0)) revert InvalidRecipient();

        AttestationRequest memory request = AttestationRequest({
            schema: verifiedAccountSchema,
            data: AttestationRequestData({
                recipient: recipient,
                expirationTime: 0,
                revocable: true,
                refUID: bytes32(0),
                data: abi.encode(true),
                value: 0
            })
        });

        bytes32 uid = _EAS.attest(request);
        emit AttestationCreated(recipient, uid);
        return uid;
    }
}

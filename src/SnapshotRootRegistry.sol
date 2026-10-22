// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.21;

/// @title SnapshotRootRegistry (PROTOTYPE)
/// @notice Published roots of a membership snapshot, and which of them a
///         verifier still accepts.
/// @dev A snapshot root is computed off-chain by an open rule
///      (circuits/scripts/coinbase-snapshot/build-snapshot.js) at a stated
///      block, so anyone can rebuild it and compare. This contract only
///      records what the publisher posted and answers "is this root recent
///      enough". Recency IS the revocation check: a wallet revoked after a
///      root was built stays in that root, so a root is accepted only while it
///      is among the newest `acceptedRoots`. Both knobs are meant to be tuned
///      in operation, hence setters rather than constants.
contract SnapshotRootRegistry {
    struct Entry {
        bytes32 root;
        uint64 blockNumber;
        uint64 publishedAt;
    }

    address public owner;
    address public publisher;
    /// How many of the newest roots verify. 1 = only the latest; 2 = also the
    /// one before, so a proof started just before an update still lands.
    uint8 public acceptedRoots;

    Entry[] private _entries;
    /// root => 1 + its LATEST index in _entries; 0 means never published.
    mapping(bytes32 => uint256) private _position;

    event Published(bytes32 indexed root, uint64 blockNumber, uint256 index);
    event AcceptedRootsChanged(uint8 acceptedRoots);
    event PublisherChanged(address publisher);
    event OwnerChanged(address owner);

    error NotOwner();
    error NotPublisher();
    error BlockNotAfterLatest(uint64 latest, uint64 given);
    error ZeroRoot();
    error AcceptedRootsOutOfRange(uint8 given);
    error ZeroAddress();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(address _publisher, uint8 _acceptedRoots) {
        if (_publisher == address(0)) revert ZeroAddress();
        if (_acceptedRoots == 0) revert AcceptedRootsOutOfRange(_acceptedRoots);
        owner = msg.sender;
        publisher = _publisher;
        acceptedRoots = _acceptedRoots;
    }

    /// @notice Record the root built at `blockNumber`.
    function publish(bytes32 root, uint64 blockNumber) external {
        if (msg.sender != publisher) revert NotPublisher();
        if (root == bytes32(0)) revert ZeroRoot();
        uint256 n = _entries.length;
        if (n != 0 && blockNumber <= _entries[n - 1].blockNumber) {
            revert BlockNotAfterLatest(_entries[n - 1].blockNumber, blockNumber);
        }
        // The same set can come back (a wallet added, then revoked), giving a
        // root published before. It is the current set again, so it moves to
        // the newest position; the latest position is the one that counts.
        _entries.push(Entry(root, blockNumber, uint64(block.timestamp)));
        _position[root] = n + 1;
        emit Published(root, blockNumber, n);
    }

    /// @notice True when `root` is one of the newest `acceptedRoots` published.
    function isAcceptedRoot(bytes32 root) public view returns (bool) {
        uint256 pos = _position[root];
        if (pos == 0) return false;
        return _entries.length - pos < acceptedRoots;
    }

    function latest() external view returns (Entry memory) {
        return _entries[_entries.length - 1];
    }

    function count() external view returns (uint256) {
        return _entries.length;
    }

    function setAcceptedRoots(uint8 n) external onlyOwner {
        if (n == 0) revert AcceptedRootsOutOfRange(n);
        acceptedRoots = n;
        emit AcceptedRootsChanged(n);
    }

    function setPublisher(address p) external onlyOwner {
        if (p == address(0)) revert ZeroAddress();
        publisher = p;
        emit PublisherChanged(p);
    }

    function transferOwnership(address o) external onlyOwner {
        if (o == address(0)) revert ZeroAddress();
        owner = o;
        emit OwnerChanged(o);
    }
}

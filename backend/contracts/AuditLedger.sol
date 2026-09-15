// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract AuditLedger {
    address public owner;

    event AuditAnchored(
        uint256 indexed sequenceNumber,
        string auditIdHash,
        string eventHash,
        uint256 blockTimestamp
    );

    struct AuditAnchor {
        uint256 sequenceNumber;
        string auditIdHash;
        string eventHash;
        string previousAuditHash;
        string eventTypeHash;
        uint256 timestamp;
    }

    // Mapping from sequenceNumber to AuditAnchor
    mapping(uint256 => AuditAnchor) public anchors;
    uint256 public totalAnchors;

    constructor() {
        owner = msg.sender;
    }

    function appendAuditAnchor(
        uint256 sequenceNumber,
        string memory auditIdHash,
        string memory eventHash,
        string memory previousAuditHash,
        string memory eventTypeHash,
        uint256 timestamp
    ) public {
        // We only allow appending sequentially or tracking appropriately.
        // For simplicity and to prevent rewrites, check if it already exists
        require(bytes(anchors[sequenceNumber].eventHash).length == 0, "Anchor already exists for this sequence number");

        anchors[sequenceNumber] = AuditAnchor({
            sequenceNumber: sequenceNumber,
            auditIdHash: auditIdHash,
            eventHash: eventHash,
            previousAuditHash: previousAuditHash,
            eventTypeHash: eventTypeHash,
            timestamp: timestamp
        });
        
        totalAnchors++;

        emit AuditAnchored(sequenceNumber, auditIdHash, eventHash, block.timestamp);
    }
}

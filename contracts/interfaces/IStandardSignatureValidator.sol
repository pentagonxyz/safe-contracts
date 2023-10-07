// SPDX-License-Identifier: LGPL-3.0-only
// Code here is for the standard EIP-1271 interface, copied from newer commit `1cfa95710057e33832600e6b9ad5ececca8f7839` to `safe-global/safe-contracts`
pragma solidity >=0.7.0 <0.9.0;

contract IStandardSignatureValidatorConstants {
    // bytes4(keccak256("isValidSignature(bytes32,bytes)")
    bytes4 internal constant EIP1271_MAGIC_VALUE = 0x1626ba7e;
}

abstract contract IStandardSignatureValidator is IStandardSignatureValidatorConstants {
    /**
     * @notice EIP1271 method to validate a signature.
     * @param _hash Hash of the data signed on the behalf of address(this).
     * @param _signature Signature byte array associated with _data.
     *
     * MUST return the bytes4 magic value 0x1626ba7e when function passes.
     * MUST NOT modify state (using STATICCALL for solc < 0.5, view modifier for solc > 0.5)
     * MUST allow external calls
     */
    function isValidSignature(bytes32 _hash, bytes memory _signature) external view virtual returns (bytes4);
}

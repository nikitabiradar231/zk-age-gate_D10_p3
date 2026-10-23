// SPDX-License-Identifier: MIT
pragma solidity >=0.8.21;

/**
 * @title IAgeVerifier
 * @notice Standard interface for the generated Barretenberg UltraHonk age-gate verifier contract.
 */
interface IAgeVerifier {
    /**
     * @notice Verifies an UltraHonk zk-SNARK proof.
     * @param proof The serialized proof bytes produced by Barretenberg.
     * @param publicInputs The canonical list of 32-byte public inputs.
     * @return True if the proof is cryptographically valid, false otherwise.
     */
    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool);
}

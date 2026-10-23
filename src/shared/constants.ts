import { ethers } from "ethers";

/**
 * Constants for the Slow Bloom Festival and AgeGate verification system.
 */

export const FESTIVAL_NAME = "Slow Bloom";

// Truncate hash to 31 bytes to strictly fit within BN254 scalar field:
const rawContextHash = ethers.keccak256(ethers.toUtf8Bytes("Slow Bloom 2026"));
const rawContextBytes = ethers.getBytes(rawContextHash);
let contextField = 0n;
for (let i = 0; i < 31; i++) {
  contextField = (contextField << 8n) + BigInt(rawContextBytes[i]);
}

/// Domain-separated context identifier for Slow Bloom 2026.
/// Formatted as canonical bytes32 fitting within BN254 scalar field.
export const FESTIVAL_CONTEXT = "0x" + contextField.toString(16).padStart(64, "0").toLowerCase();

/// Pass type identifier for the Late-Night Festival Pass.
export const PASS_TYPE_LATE_NIGHT = 1n;

/// Minimum age required by festival policy.
export const REQUIRED_MIN_AGE = 18;

/// Maximum age of a proof in seconds before it is rejected as stale.
export const PROOF_MAX_AGE_SECONDS = 3600; // 1 hour

/// Deterministic test keypair for synthetic testing (door partner issuer).
/// NEVER use in production; generated purely for offline reproducible unit and integration tests.
export const TEST_ISSUER_PRIVATE_KEY_HEX =
  "c87702da708451dd58b33919ac97d41a43e4d51315847fa30e41865d63718810";

/// Reference test date for synthetic tests (YYYY-MM-DD): 2026-10-23
export const DEFAULT_TEST_REF_YEAR = 2026;
export const DEFAULT_TEST_REF_MONTH = 10;
export const DEFAULT_TEST_REF_DAY = 23;

import { ethers } from "ethers";

/**
 * Shared encoding and cryptographic formatting utilities for zk-age-gate.
 */

// BN254 scalar field order:
export const BN254_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/**
 * Truncates / maps a 32-byte hash into the BN254 field safely by taking the first 31 bytes.
 */
export function hashToField(hashBytes: Uint8Array | string): bigint {
  const bytes = typeof hashBytes === "string" ? ethers.getBytes(hashBytes) : hashBytes;
  if (bytes.length < 31) {
    throw new Error("Input bytes must be at least 31 bytes long");
  }
  let field = 0n;
  for (let i = 0; i < 31; i++) {
    field = (field << 8n) + BigInt(bytes[i]);
  }
  return field;
}

/**
 * Formats a BigInt or hex string as a 32-byte hex string (0x-prefixed, 64 hex characters).
 */
export function toBytes32(value: bigint | number | string): string {
  if (typeof value === "string" && value.startsWith("0x") && value.length === 66) {
    return value.toLowerCase();
  }
  const bigVal = BigInt(value);
  return "0x" + bigVal.toString(16).padStart(64, "0").toLowerCase();
}

/**
 * Civil calendar date conversion matching Solidity AgeGate.timestampToDate.
 * Converts Unix timestamp (seconds) into UTC calendar year, month, day.
 */
export function timestampToDate(timestampSeconds: number | bigint): {
  year: number;
  month: number;
  day: number;
} {
  const ts = BigInt(timestampSeconds);
  const z = ts / 86400n + 719468n;
  const era = z / 146097n;
  const doe = z - era * 146097n;
  const yoe = (doe - doe / 1460n + doe / 36524n - doe / 146096n) / 365n;
  let y = yoe + era * 400n;
  const doy = doe - (365n * yoe + yoe / 4n - yoe / 100n);
  const mp = (5n * doy + 2n) / 153n;
  const d = doy - (153n * mp + 2n) / 5n + 1n;
  const m = mp < 10n ? mp + 3n : mp - 9n;
  y = mp >= 10n ? y + 1n : y;
  return {
    year: Number(y),
    month: Number(m),
    day: Number(d),
  };
}

/**
 * Converts UTC calendar year, month, day to Unix timestamp in seconds (at 00:00:00 UTC).
 */
export function dateToTimestamp(year: number, month: number, day: number): number {
  return Math.floor(Date.UTC(year, month - 1, day, 0, 0, 0) / 1000);
}


/**
 * Checks if a given calendar date has reached their 18th birthday on the reference date.
 */
export function isEligibleAge(
  birth: { year: number; month: number; day: number },
  ref: { year: number; month: number; day: number }
): boolean {
  const eighteenthYear = birth.year + 18;
  let ey = eighteenthYear;
  let em = birth.month;
  let ed = birth.day;

  // Leap-day birthday rule: Feb 29 baby turns 18 on March 1st in non-leap years
  if (birth.month === 2 && birth.day === 29) {
    em = 3;
    ed = 1;
  }

  if (ref.year > ey) return true;
  if (ref.year < ey) return false;
  if (ref.month > em) return true;
  if (ref.month < em) return false;
  return ref.day >= ed;
}

/**
 * Packs credential payload exactly matching Noir circuit pack_credential_payload:
 * 32 bytes: credential_id
 * 2 bytes: birth_year (big endian)
 * 1 byte: birth_month
 * 1 byte: birth_day
 * 2 bytes: expiry_year (big endian)
 * 1 byte: expiry_month
 * 1 byte: expiry_day
 * 16 bytes: buyer_id_commitment
 * Total: 56 bytes.
 */
export function packCredentialPayload(params: {
  credentialId: Uint8Array;
  birthYear: number;
  birthMonth: number;
  birthDay: number;
  expiryYear: number;
  expiryMonth: number;
  expiryDay: number;
  buyerIdCommitment: Uint8Array;
}): Uint8Array {
  const payload = new Uint8Array(56);
  payload.set(params.credentialId.subarray(0, 32), 0);
  payload[32] = (params.birthYear >> 8) & 0xff;
  payload[33] = params.birthYear & 0xff;
  payload[34] = params.birthMonth & 0xff;
  payload[35] = params.birthDay & 0xff;
  payload[36] = (params.expiryYear >> 8) & 0xff;
  payload[37] = params.expiryYear & 0xff;
  payload[38] = params.expiryMonth & 0xff;
  payload[39] = params.expiryDay & 0xff;
  payload.set(params.buyerIdCommitment.subarray(0, 16), 40);
  return payload;
}

/**
 * Computes the issuer public key hash from 32-byte pub_x and 32-byte pub_y.
 */
export function computeIssuerPubKeyHash(pubX: Uint8Array, pubY: Uint8Array): bigint {
  const keyBytes = new Uint8Array(64);
  keyBytes.set(pubX, 0);
  keyBytes.set(pubY, 32);
  const hash = ethers.keccak256(keyBytes);
  return hashToField(hash);
}

/**
 * Derives the deterministic nullifier matching the Noir circuit:
 * nullifier = keccak256(credential_id[32] || buyer_secret[32] || festival_context[32] || pass_type[32])
 * mapped to BN254 field.
 */
export function computeNullifier(params: {
  credentialId: Uint8Array;
  buyerSecret: Uint8Array;
  festivalContext: Uint8Array | string;
  passType: bigint | number;
}): bigint {
  const contextBytes =
    typeof params.festivalContext === "string"
      ? ethers.getBytes(params.festivalContext)
      : params.festivalContext;
  const passTypeBytes = ethers.getBytes(toBytes32(params.passType));

  const preimage = new Uint8Array(128);
  preimage.set(params.credentialId.subarray(0, 32), 0);
  preimage.set(params.buyerSecret.subarray(0, 32), 32);
  preimage.set(contextBytes.subarray(0, 32), 64);
  preimage.set(passTypeBytes.subarray(0, 32), 96);

  const hash = ethers.keccak256(preimage);
  return hashToField(hash);
}

/**
 * Type definitions for zk-age-gate buyer-side client and credential management.
 */

export interface CalendarDate {
  year: number;
  month: number; // 1 - 12
  day: number; // 1 - 31
}

export interface IssuerKeyPair {
  privateKeyHex: string;
  pubKeyXHex: string;
  pubKeyYHex: string;
  pubKeyHash: bigint;
}

export interface AgeCredential {
  /// Unique 32-byte identifier issued by the door partner
  credentialIdHex: string;
  /// Authentic birth date verified off-chain by the door partner
  birthDate: CalendarDate;
  /// Credential expiration policy date
  expiryDate: CalendarDate;
  /// Secret salt belonging solely to the buyer
  buyerSecretHex: string;
  /// Issuer public key coordinates on secp256k1 (32 bytes each)
  issuerPubKey: {
    xHex: string;
    yHex: string;
  };
  /// Issuer ECDSA signature over the credential payload (64 bytes: r || s, low-S)
  signatureHex: string;
}

export interface ClaimRequest {
  /// The Ethereum address of the claimant (msg.sender)
  claimantAddress: string;
  /// Festival context identifier (Slow Bloom 2026)
  festivalContext?: string;
  /// Pass type identifier (e.g. 1 for late-night pass)
  passType?: bigint;
  /// Contract-authorized reference date
  referenceDate?: CalendarDate;
  /// Local claim timestamp (in seconds)
  claimTimestamp?: number;
}

export interface ProofOutput {
  /// Raw proof bytes formatted as hex string
  proofHex: string;
  /// Canonical list of 9 bytes32 public inputs matching Solidity verifier expectations
  publicInputs: string[];
  /// Deterministic nullifier for replay protection (bytes32 hex)
  nullifierHex: string;
  /// Claimant address bound to the proof
  claimant: string;
  /// Unix timestamp when claim was prepared
  claimTimestamp: number;
  /// Reference date used for age verification
  referenceDate: CalendarDate;
}

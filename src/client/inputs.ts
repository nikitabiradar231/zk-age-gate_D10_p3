import { ethers } from "ethers";
import {
  computeIssuerPubKeyHash,
  computeNullifier,
  isEligibleAge,
  timestampToDate,
  toBytes32,
} from "../shared/encoding";
import {
  FESTIVAL_CONTEXT,
  PASS_TYPE_LATE_NIGHT,
} from "../shared/constants";
import { AgeCredential, CalendarDate, ClaimRequest } from "./types";

export interface PreparedProverInputs {
  publicInputs: {
    claimant: string;
    festivalContext: string;
    passType: bigint;
    refYear: number;
    refMonth: number;
    refDay: number;
    claimTimestamp: number;
    issuerPubKeyHash: bigint;
    nullifier: bigint;
  };
  privateWitness: {
    birthYear: number;
    birthMonth: number;
    birthDay: number;
    expiryYear: number;
    expiryMonth: number;
    expiryDay: number;
    credentialId: number[];
    buyerSecret: number[];
    issuerPubX: number[];
    issuerPubY: number[];
    issuerSignature: number[];
  };
  solidityPublicInputs: string[];
}

/**
 * Validates buyer credentials and prepares all circuit witness and public inputs locally.
 */
export function buildProverInputs(
  credential: AgeCredential,
  request: ClaimRequest
): PreparedProverInputs {
  // 1. Validate claimant address
  if (!ethers.isAddress(request.claimantAddress)) {
    throw new Error(`Invalid Ethereum address: ${request.claimantAddress}`);
  }
  const claimantField = BigInt(request.claimantAddress).toString();

  // 2. Determine reference date and timestamp
  const claimTimestamp = request.claimTimestamp ?? Math.floor(Date.now() / 1000);
  const refDate: CalendarDate = request.referenceDate ?? timestampToDate(claimTimestamp);

  // 3. Client-side sanity check: Assert eligibility before spending compute on proving
  if (!isEligibleAge(credential.birthDate, refDate)) {
    throw new Error(
      `Underage applicant: Birth date ${credential.birthDate.year}-${credential.birthDate.month}-${credential.birthDate.day} does not meet 18+ requirement on reference date ${refDate.year}-${refDate.month}-${refDate.day}`
    );
  }

  // 4. Validate context and pass type
  const festivalContextHex = request.festivalContext ?? FESTIVAL_CONTEXT;
  const passType = request.passType ?? PASS_TYPE_LATE_NIGHT;

  // 5. Parse byte arrays
  const credIdBytes = Array.from(ethers.getBytes(credential.credentialIdHex));
  const buyerSecretBytes = Array.from(ethers.getBytes(credential.buyerSecretHex));
  const issuerPubXBytes = Array.from(ethers.getBytes(credential.issuerPubKey.xHex));
  const issuerPubYBytes = Array.from(ethers.getBytes(credential.issuerPubKey.yHex));
  const sigBytes = Array.from(ethers.getBytes(credential.signatureHex));

  // 6. Compute issuer public key commitment hash
  const issuerPubKeyHash = computeIssuerPubKeyHash(
    new Uint8Array(issuerPubXBytes),
    new Uint8Array(issuerPubYBytes)
  );

  // 7. Derive deterministic nullifier
  const nullifier = computeNullifier({
    credentialId: new Uint8Array(credIdBytes),
    buyerSecret: new Uint8Array(buyerSecretBytes),
    festivalContext: festivalContextHex,
    passType,
  });

  // 8. Prepare canonical 9 public inputs for Solidity verifier calldata
  const solidityPublicInputs: string[] = [
    toBytes32(claimantField),
    toBytes32(festivalContextHex),
    toBytes32(passType),
    toBytes32(refDate.year),
    toBytes32(refDate.month),
    toBytes32(refDate.day),
    toBytes32(claimTimestamp),
    toBytes32(issuerPubKeyHash),
    toBytes32(nullifier),
  ];

  return {
    publicInputs: {
      claimant: claimantField,
      festivalContext: festivalContextHex,
      passType,
      refYear: refDate.year,
      refMonth: refDate.month,
      refDay: refDate.day,
      claimTimestamp,
      issuerPubKeyHash,
      nullifier,
    },
    privateWitness: {
      birthYear: credential.birthDate.year,
      birthMonth: credential.birthDate.month,
      birthDay: credential.birthDate.day,
      expiryYear: credential.expiryDate.year,
      expiryMonth: credential.expiryDate.month,
      expiryDay: credential.expiryDate.day,
      credentialId: credIdBytes,
      buyerSecret: buyerSecretBytes,
      issuerPubX: issuerPubXBytes,
      issuerPubY: issuerPubYBytes,
      issuerSignature: sigBytes,
    },
    solidityPublicInputs,
  };
}

/**
 * Generates TOML string for Noir witness execution.
 */
export function formatProverToml(inputs: PreparedProverInputs): string {
  const { publicInputs, privateWitness } = inputs;
  return `# Public Inputs
claimant = "${publicInputs.claimant}"
festival_context = "${publicInputs.festivalContext}"
pass_type = "${publicInputs.passType.toString()}"
ref_year = ${publicInputs.refYear}
ref_month = ${publicInputs.refMonth}
ref_day = ${publicInputs.refDay}
claim_timestamp = ${publicInputs.claimTimestamp}
issuer_pubkey_hash = "${publicInputs.issuerPubKeyHash.toString()}"
nullifier = "${publicInputs.nullifier.toString()}"

# Private Witness (Local Only)
birth_year = ${privateWitness.birthYear}
birth_month = ${privateWitness.birthMonth}
birth_day = ${privateWitness.birthDay}
expiry_year = ${privateWitness.expiryYear}
expiry_month = ${privateWitness.expiryMonth}
expiry_day = ${privateWitness.expiryDay}
credential_id = ${JSON.stringify(privateWitness.credentialId)}
buyer_secret = ${JSON.stringify(privateWitness.buyerSecret)}
issuer_pub_x = ${JSON.stringify(privateWitness.issuerPubX)}
issuer_pub_y = ${JSON.stringify(privateWitness.issuerPubY)}
issuer_signature = ${JSON.stringify(privateWitness.issuerSignature)}
`;
}

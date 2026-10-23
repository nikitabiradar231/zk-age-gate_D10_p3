import { secp256k1 } from "@noble/curves/secp256k1";
import { ethers } from "ethers";
import {
  computeIssuerPubKeyHash,
  packCredentialPayload,
} from "../shared/encoding";
import { TEST_ISSUER_PRIVATE_KEY_HEX } from "../shared/constants";
import { AgeCredential, CalendarDate, IssuerKeyPair } from "./types";

/**
 * Derives the issuer public key coordinates and contract commitment from an ECDSA private key.
 */
export function getIssuerKeyPair(privateKeyHex: string = TEST_ISSUER_PRIVATE_KEY_HEX): IssuerKeyPair {
  const cleanPriv = privateKeyHex.startsWith("0x") ? privateKeyHex.slice(2) : privateKeyHex;
  const pubBytes = secp256k1.getPublicKey(cleanPriv, false); // 65 bytes: 0x04 || x || y
  const pubX = pubBytes.subarray(1, 33);
  const pubY = pubBytes.subarray(33, 65);
  const pubKeyHash = computeIssuerPubKeyHash(pubX, pubY);

  return {
    privateKeyHex: "0x" + cleanPriv,
    pubKeyXHex: ethers.hexlify(pubX),
    pubKeyYHex: ethers.hexlify(pubY),
    pubKeyHash,
  };
}

/**
 * Creates a cryptographically authentic AgeCredential signed by the door partner.
 * Simulates the off-chain identity verification at the festival door.
 */
export function createAgeCredential(params: {
  birthDate: CalendarDate;
  expiryDate?: CalendarDate;
  credentialIdHex?: string;
  buyerSecretHex?: string;
  issuerPrivateKeyHex?: string;
}): AgeCredential {
  const issuerKey = getIssuerKeyPair(params.issuerPrivateKeyHex || TEST_ISSUER_PRIVATE_KEY_HEX);

  // Generate or parse credential ID (32 bytes)
  const credentialIdBytes = params.credentialIdHex
    ? ethers.getBytes(params.credentialIdHex)
    : ethers.randomBytes(32);

  // Generate or parse buyer secret (32 bytes)
  const buyerSecretBytes = params.buyerSecretHex
    ? ethers.getBytes(params.buyerSecretHex)
    : ethers.randomBytes(32);

  // Default expiry: 5 years from reference
  const expiryDate: CalendarDate = params.expiryDate || {
    year: params.birthDate.year + 25,
    month: 12,
    day: 31,
  };

  // Buyer ID commitment: lowest 16 bytes of buyerSecret (matching circuit)
  const buyerIdCommitment = buyerSecretBytes.subarray(16, 32);

  // Pack 56-byte credential payload
  const payload = packCredentialPayload({
    credentialId: credentialIdBytes,
    birthYear: params.birthDate.year,
    birthMonth: params.birthDate.month,
    birthDay: params.birthDate.day,
    expiryYear: expiryDate.year,
    expiryMonth: expiryDate.month,
    expiryDay: expiryDate.day,
    buyerIdCommitment,
  });

  // Hash payload with keccak256
  const payloadHash = ethers.keccak256(payload);
  const payloadHashBytes = ethers.getBytes(payloadHash);

  // Sign using issuer private key with low-S (BIP 62)
  const privClean = issuerKey.privateKeyHex.slice(2);
  const sig = secp256k1.sign(payloadHashBytes, privClean, { lowS: true });
  const rawSignature = sig.toCompactRawBytes();

  return {
    credentialIdHex: ethers.hexlify(credentialIdBytes),
    birthDate: params.birthDate,
    expiryDate,
    buyerSecretHex: ethers.hexlify(buyerSecretBytes),
    issuerPubKey: {
      xHex: issuerKey.pubKeyXHex,
      yHex: issuerKey.pubKeyYHex,
    },
    signatureHex: ethers.hexlify(rawSignature),
  };
}

/**
 * Verifies the door partner signature off-chain before initiating local ZK proof generation.
 */
export function verifyCredentialSignature(credential: AgeCredential): boolean {
  const credentialIdBytes = ethers.getBytes(credential.credentialIdHex);
  const buyerSecretBytes = ethers.getBytes(credential.buyerSecretHex);
  const buyerIdCommitment = buyerSecretBytes.subarray(16, 32);

  const payload = packCredentialPayload({
    credentialId: credentialIdBytes,
    birthYear: credential.birthDate.year,
    birthMonth: credential.birthDate.month,
    birthDay: credential.birthDate.day,
    expiryYear: credential.expiryDate.year,
    expiryMonth: credential.expiryDate.month,
    expiryDay: credential.expiryDate.day,
    buyerIdCommitment,
  });

  const payloadHash = ethers.keccak256(payload);
  const payloadHashBytes = ethers.getBytes(payloadHash);
  const sigBytes = ethers.getBytes(credential.signatureHex);

  const pubX = ethers.getBytes(credential.issuerPubKey.xHex);
  const pubY = ethers.getBytes(credential.issuerPubKey.yHex);
  const uncompressedPub = new Uint8Array(65);
  uncompressedPub[0] = 0x04;
  uncompressedPub.set(pubX, 1);
  uncompressedPub.set(pubY, 33);

  return secp256k1.verify(sigBytes, payloadHashBytes, uncompressedPub);
}

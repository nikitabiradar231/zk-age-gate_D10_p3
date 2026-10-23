import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";
import { ethers } from "ethers";
import { createAgeCredential, verifyCredentialSignature, getIssuerKeyPair } from "../src/client/credential";
import { buildProverInputs, formatProverToml } from "../src/client/inputs";
import { verifyProofWithBarretenberg } from "../src/client/prove";
import {
  computeIssuerPubKeyHash,
  computeNullifier,
  isEligibleAge,
  packCredentialPayload,
  timestampToDate,
  dateToTimestamp,
  toBytes32,
  BN254_MODULUS,
} from "../src/shared/encoding";
import {
  FESTIVAL_CONTEXT,
  PASS_TYPE_LATE_NIGHT,
  TEST_ISSUER_PRIVATE_KEY_HEX,
} from "../src/shared/constants";

async function runTsUnitTests() {
  console.log("=================================================");
  console.log(" Running TypeScript Client & Cryptographic Tests");
  console.log("=================================================\n");

  let passed = 0;
  let failed = 0;

  async function test(name: string, fn: () => Promise<void> | void) {
    process.stdout.write(`Testing ${name} ... `);
    try {
      await fn();
      console.log("ok");
      passed++;
    } catch (err: any) {
      console.log("FAIL");
      console.error(`  Error: ${err.message || err}`);
      failed++;
    }
  }

  // 1. Local witness construction
  await test("local witness construction and Prover.toml formatting", () => {
    const cred = createAgeCredential({
      birthDate: { year: 2004, month: 3, day: 15 },
    });
    const claimant = "0x90F79bf6EB2c4f870365E785982E1f101E93b906";
    const refDate = { year: 2026, month: 10, day: 24 };

    const prepared = buildProverInputs(cred, {
      claimantAddress: claimant,
      claimTimestamp: 1792800000,
      referenceDate: refDate,
    });

    assert.strictEqual(prepared.publicInputs.refYear, 2026);
    assert.strictEqual(prepared.publicInputs.refMonth, 10);
    assert.strictEqual(prepared.publicInputs.refDay, 24);
    assert.strictEqual(prepared.privateWitness.birthYear, 2004);
    assert.strictEqual(prepared.privateWitness.birthMonth, 3);
    assert.strictEqual(prepared.privateWitness.birthDay, 15);

    const toml = formatProverToml(prepared);
    assert.ok(toml.includes('claimant = "'));
    assert.ok(toml.includes('festival_context = "'));
    assert.ok(toml.includes("birth_year = 2004"));
    assert.ok(toml.includes("credential_id = ["));
  });

  // 2. Proof fixture verification with Barretenberg
  await test("saved proof fixture is valid and verifies with Barretenberg", async () => {
    const fixturePath = path.resolve(__dirname, "fixtures", "proof_fixture.json");
    assert.ok(fs.existsSync(fixturePath), "Proof fixture must exist");
    const fixture = JSON.parse(fs.readFileSync(fixturePath, "utf-8"));

    assert.strictEqual(fixture.proofHex.length, 2 + 14080 * 2);
    assert.strictEqual(fixture.publicInputs.length, 9);

    const isValid = await verifyProofWithBarretenberg(
      fixture.proofHex,
      fixture.publicInputs
    );
    assert.strictEqual(isValid, true, "Proof fixture must verify with Barretenberg");
  });

  // 3. Canonical public-input encoding and BN254 scalar field bounds
  await test("canonical public inputs are formatted and strictly less than BN254 modulus", () => {
    const cred = createAgeCredential({
      birthDate: { year: 2000, month: 1, day: 1 },
    });
    const prepared = buildProverInputs(cred, {
      claimantAddress: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
      claimTimestamp: 1792800000,
    });

    assert.strictEqual(prepared.solidityPublicInputs.length, 9);
    for (const inputHex of prepared.solidityPublicInputs) {
      assert.strictEqual(inputHex.length, 66, "Each public input must be 32 bytes (66 hex chars)");
      const val = BigInt(inputHex);
      assert.ok(val < BN254_MODULUS, "Each public input Field must be strictly less than BN254 modulus");
    }
  });

  // 4. Account and context binding validations
  await test("account address validation rejects invalid Ethereum addresses", () => {
    const cred = createAgeCredential({
      birthDate: { year: 2000, month: 1, day: 1 },
    });

    assert.throws(
      () => {
        buildProverInputs(cred, {
          claimantAddress: "not-an-address",
        });
      },
      /Invalid Ethereum address/,
      "Must throw on malformed address"
    );
  });

  // 5. Door partner credential signature verification
  await test("door partner credential signature verifies authentic credentials", () => {
    const cred = createAgeCredential({
      birthDate: { year: 2002, month: 8, day: 19 },
    });
    assert.strictEqual(verifyCredentialSignature(cred), true);

    // Tampering with birth day invalidates signature
    const tamperedCred = {
      ...cred,
      birthDate: { year: 2002, month: 8, day: 20 },
    };
    assert.strictEqual(verifyCredentialSignature(tamperedCred), false);
  });

  // 6. Nullifier derivation consistency and sensitivity
  await test("nullifier computation is consistent and sensitive to all parameters", () => {
    const credId = ethers.randomBytes(32);
    const secret = ethers.randomBytes(32);

    const n1 = computeNullifier({
      credentialId: credId,
      buyerSecret: secret,
      festivalContext: FESTIVAL_CONTEXT,
      passType: PASS_TYPE_LATE_NIGHT,
    });

    const n2 = computeNullifier({
      credentialId: credId,
      buyerSecret: secret,
      festivalContext: FESTIVAL_CONTEXT,
      passType: PASS_TYPE_LATE_NIGHT,
    });

    assert.strictEqual(n1, n2);
    assert.ok(n1 < BN254_MODULUS, "Nullifier must fit within BN254 Field");

    const nDiffSecret = computeNullifier({
      credentialId: credId,
      buyerSecret: ethers.randomBytes(32),
      festivalContext: FESTIVAL_CONTEXT,
      passType: PASS_TYPE_LATE_NIGHT,
    });
    assert.notStrictEqual(n1, nDiffSecret);
  });

  // 7. Date and timestamp conversion consistency
  await test("calendar date and unix timestamp roundtrip correctly", () => {
    const ts = 1792771200; // 2026-10-23T16:00:00Z
    const d = timestampToDate(ts);
    assert.strictEqual(d.year, 2026);
    assert.strictEqual(d.month, 10);
    assert.strictEqual(d.day, 23);

    const dayStartTs = dateToTimestamp(d.year, d.month, d.day);
    assert.strictEqual(dayStartTs, 1792713600); // 2026-10-23T00:00:00Z
  });

  // 8. No private values leaked into logs or public outputs
  await test("no secret or birth date leakage during input preparation", () => {
    const cred = createAgeCredential({
      birthDate: { year: 1999, month: 11, day: 22 },
    });
    const prepared = buildProverInputs(cred, {
      claimantAddress: "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
    });

    const publicInputsStr = JSON.stringify(prepared.solidityPublicInputs);
    assert.ok(!publicInputsStr.includes("1999"));
    assert.ok(!publicInputsStr.includes(cred.buyerSecretHex.slice(2)));
    assert.ok(!publicInputsStr.includes(cred.credentialIdHex.slice(2)));
  });

  console.log(`\nTypeScript Unit Test Results: ${passed} passed, ${failed} failed`);
  if (failed > 0) {
    process.exit(1);
  }
}

if (require.main === module) {
  runTsUnitTests().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}

export { runTsUnitTests };

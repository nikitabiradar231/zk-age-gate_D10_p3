import * as assert from "assert";
import { ethers } from "ethers";
import { createAgeCredential } from "../src/client/credential";
import { buildProverInputs } from "../src/client/inputs";
import { generateAgeProof, verifyProofWithBarretenberg } from "../src/client/prove";
import {
  computeNullifier,
  isEligibleAge,
  timestampToDate,
} from "../src/shared/encoding";
import {
  FESTIVAL_CONTEXT,
  PASS_TYPE_LATE_NIGHT,
} from "../src/shared/constants";

async function runTestSuite() {
  console.log("=================================================");
  console.log(" Running Circuit & Prover Integration Tests");
  console.log("=================================================\n");

  let passed = 0;
  let failed = 0;

  async function test(name: string, fn: () => Promise<void>) {
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

  // 1. Valid adult credential generates real proof and verifies with Barretenberg
  await test("valid adult (21yo) generates and verifies proof locally", async () => {
    const cred = createAgeCredential({
      birthDate: { year: 2005, month: 4, day: 12 },
    });
    const claimant = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
    const refTimestamp = 1792771200; // 2026-10-23T16:00:00Z
    const refDate = timestampToDate(refTimestamp);

    const result = await generateAgeProof(
      cred,
      {
        claimantAddress: claimant,
        claimTimestamp: refTimestamp,
        referenceDate: refDate,
      },
      { verifyLocally: true }
    );

    assert.ok(result.proofHex.startsWith("0x"));
    assert.strictEqual(result.publicInputs.length, 9);
    assert.strictEqual(result.claimant, claimant);

    // Verify through standalone Barretenberg API
    const isBbValid = await verifyProofWithBarretenberg(
      result.proofHex,
      result.publicInputs
    );
    assert.strictEqual(isBbValid, true, "Barretenberg verification should succeed");
  });

  // 2. Underage candidate (16yo) is rejected
  await test("underage applicant (16yo) is rejected before proving", async () => {
    const cred = createAgeCredential({
      birthDate: { year: 2010, month: 6, day: 15 },
    });
    const claimant = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
    const refDate = { year: 2026, month: 10, day: 23 };

    let rejected = false;
    try {
      await generateAgeProof(cred, {
        claimantAddress: claimant,
        claimTimestamp: 1792771200,
        referenceDate: refDate,
      });
    } catch (err: any) {
      if (err.message.includes("Underage applicant") || err.message.includes("18+")) {
        rejected = true;
      }
    }
    assert.strictEqual(rejected, true, "Underage claimant must be rejected");
  });

  // 3. Exact 18th birthday boundary eligibility
  await test("exact 18th birthday boundary is eligible", async () => {
    const birthDate = { year: 2008, month: 10, day: 24 };
    const refDate = { year: 2026, month: 10, day: 24 };
    assert.strictEqual(isEligibleAge(birthDate, refDate), true);

    const cred = createAgeCredential({ birthDate });
    const inputs = buildProverInputs(cred, {
      claimantAddress: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
      claimTimestamp: 1792800000,
      referenceDate: refDate,
    });
    assert.strictEqual(inputs.publicInputs.refYear, 2026);
    assert.strictEqual(inputs.publicInputs.refMonth, 10);
    assert.strictEqual(inputs.publicInputs.refDay, 24);
  });

  // 4. One day before 18th birthday boundary ineligibility
  await test("one day before 18th birthday is ineligible", async () => {
    const birthDate = { year: 2008, month: 10, day: 25 };
    const refDate = { year: 2026, month: 10, day: 24 };
    assert.strictEqual(isEligibleAge(birthDate, refDate), false);
  });

  // 5. Leap-day birthday policy (Feb 29)
  await test("leap-day birthday policy: 18th birthday is March 1st in non-leap year", async () => {
    const leapBirthDate = { year: 2008, month: 2, day: 29 };
    // 2026 is not a leap year. On Feb 28, person has not completed 18th year
    assert.strictEqual(
      isEligibleAge(leapBirthDate, { year: 2026, month: 2, day: 28 }),
      false,
      "Must not be 18 on Feb 28"
    );
    // On March 1, 2026, person has reached their 18th birthday
    assert.strictEqual(
      isEligibleAge(leapBirthDate, { year: 2026, month: 3, day: 1 }),
      true,
      "Must be 18 on March 1"
    );
  });

  // 6. Tampered birth date fails door partner signature verification
  await test("tampered birth date fails signature authenticity check", async () => {
    const cred = createAgeCredential({
      birthDate: { year: 2010, month: 5, day: 20 },
    });
    // Attacker modifies birth date to appear 26 years old
    const tamperedCred = {
      ...cred,
      birthDate: { year: 2000, month: 5, day: 20 },
    };

    let sigFailed = false;
    try {
      await generateAgeProof(tamperedCred, {
        claimantAddress: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        claimTimestamp: 1792771200,
        referenceDate: { year: 2026, month: 10, day: 23 },
      });
    } catch (err: any) {
      if (err.message.includes("signature verification failed")) {
        sigFailed = true;
      }
    }
    assert.strictEqual(sigFailed, true, "Tampered birth date must fail signature check");
  });

  // 7. Forged issuer signature with untrusted key
  await test("untrusted issuer private key produces mismatched issuer commitment", async () => {
    // Generate a rogue keypair
    const roguePrivKey = "0x" + "aa".repeat(32);
    const rogueCred = createAgeCredential({
      birthDate: { year: 2000, month: 1, day: 1 },
      issuerPrivateKeyHex: roguePrivKey,
    });
    const inputs = buildProverInputs(rogueCred, {
      claimantAddress: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
      claimTimestamp: 1792771200,
    });
    // Circuit and contract check issuer_pubkey_hash against authorized commitment
    const authorizedIssuerHash = 205625464134440813354427494490159491763784157053535282496464670008581026090n;
    assert.notStrictEqual(
      inputs.publicInputs.issuerPubKeyHash,
      authorizedIssuerHash,
      "Rogue issuer hash must not match contract authorized hash"
    );
  });

  // 8. Privacy check: Birth date and secrets absent from public outputs
  await test("zero disclosure: birth date, credential ID, and secrets remain private", async () => {
    const cred = createAgeCredential({
      birthDate: { year: 2003, month: 8, day: 19 },
    });
    const inputs = buildProverInputs(cred, {
      claimantAddress: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
      claimTimestamp: 1792771200,
      referenceDate: { year: 2026, month: 10, day: 23 },
    });

    const publicInputsStr = JSON.stringify(inputs.solidityPublicInputs);

    // Birth year 2003 should NOT appear as an encoded public input
    const birthYearHex = ethers.toBeHex(2003, 32);
    assert.strictEqual(
      inputs.solidityPublicInputs.includes(birthYearHex),
      false,
      "Birth year must not appear in public inputs"
    );

    // Exact birth month (8) and day (19) must NOT appear as public inputs
    const birthDayHex = ethers.toBeHex(19, 32);
    assert.strictEqual(
      inputs.solidityPublicInputs.includes(birthDayHex),
      false,
      "Birth day must not appear in public inputs"
    );

    // Secret salt should NOT appear in public inputs
    assert.strictEqual(
      publicInputsStr.includes(cred.buyerSecretHex.slice(2)),
      false,
      "Buyer secret salt must not appear in public inputs"
    );

    // Credential ID should NOT appear in public inputs
    assert.strictEqual(
      publicInputsStr.includes(cred.credentialIdHex.slice(2)),
      false,
      "Credential ID must not appear in public inputs"
    );
  });

  // 9. Nullifier determinism and domain separation
  await test("nullifier is deterministic and domain-separated by festival context and pass type", async () => {
    const credId = ethers.randomBytes(32);
    const buyerSecret = ethers.randomBytes(32);

    const nullifier1 = computeNullifier({
      credentialId: credId,
      buyerSecret,
      festivalContext: FESTIVAL_CONTEXT,
      passType: PASS_TYPE_LATE_NIGHT,
    });

    const nullifier2 = computeNullifier({
      credentialId: credId,
      buyerSecret,
      festivalContext: FESTIVAL_CONTEXT,
      passType: PASS_TYPE_LATE_NIGHT,
    });

    assert.strictEqual(nullifier1, nullifier2, "Nullifier must be deterministic");

    const nullifierDifferentPass = computeNullifier({
      credentialId: credId,
      buyerSecret,
      festivalContext: FESTIVAL_CONTEXT,
      passType: 2n, // Different pass type (e.g. VIP Day Pass)
    });

    assert.notStrictEqual(
      nullifier1,
      nullifierDifferentPass,
      "Nullifier must differ across pass types"
    );

    const nullifierDifferentFestival = computeNullifier({
      credentialId: credId,
      buyerSecret,
      festivalContext: ethers.keccak256(ethers.toUtf8Bytes("OTHER_FESTIVAL_2026")),
      passType: PASS_TYPE_LATE_NIGHT,
    });

    assert.notStrictEqual(
      nullifier1,
      nullifierDifferentFestival,
      "Nullifier must differ across festival contexts"
    );
  });

  console.log(`\nCircuit Test Results: ${passed} passed, ${failed} failed`);
  if (failed > 0) {
    process.exit(1);
  }
}

// Execute when run via ts-node
if (require.main === module) {
  runTestSuite().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}

export { runTestSuite };

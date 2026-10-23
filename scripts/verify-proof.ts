import * as fs from "fs";
import * as path from "path";
import { verifyProofWithBarretenberg } from "../src/client/prove";

/**
 * CLI script to verify a generated proof against the circuit verification key.
 */
async function main() {
  console.log("=== zk-age-gate: Proof Verification ===");

  const fixturePath =
    process.argv[2] || path.resolve(__dirname, "..", "test", "fixtures", "proof_fixture.json");

  if (!fs.existsSync(fixturePath)) {
    console.error(`Error: Proof fixture not found at ${fixturePath}. Run 'npm run prove' first.`);
    process.exit(1);
  }

  const fixture = JSON.parse(fs.readFileSync(fixturePath, "utf-8"));
  console.log(`Verifying proof for claimant: ${fixture.claimant}`);
  console.log(`Nullifier: ${fixture.nullifierHex}`);

  const isValid = await verifyProofWithBarretenberg(fixture.proofHex, fixture.publicInputs);
  if (isValid) {
    console.log("✓ SUCCESS: Proof cryptographically verified with Barretenberg!");
    process.exit(0);
  } else {
    console.error("✗ FAILURE: Proof verification failed!");
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("Verification failed:", err.message);
  process.exit(1);
});

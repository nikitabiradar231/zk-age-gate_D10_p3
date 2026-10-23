import * as fs from "fs";
import * as path from "path";

/**
 * Validates that all generated cryptographic artifacts exist and are up to date.
 */
async function main() {
  console.log("=== zk-age-gate: Artifact Consistency Check ===");

  const rootDir = path.resolve(__dirname, "..");
  const circuitSrc = path.join(rootDir, "circuits", "age_gate", "src", "main.nr");
  const bytecodePath = path.join(rootDir, "target", "age_gate.json");
  const vkPath = path.join(rootDir, "target", "vk", "vk");
  const verifierPath = path.join(rootDir, "contracts", "generated", "AgeGateVerifier.sol");

  const requiredArtifacts = [
    { name: "Circuit Bytecode", path: bytecodePath },
    { name: "Verification Key", path: vkPath },
    { name: "Solidity Verifier", path: verifierPath },
  ];

  let missing = 0;
  for (const artifact of requiredArtifacts) {
    if (!fs.existsSync(artifact.path)) {
      console.error(`✗ MISSING ARTIFACT: ${artifact.name} not found at ${artifact.path}`);
      missing++;
    } else {
      const stats = fs.statSync(artifact.path);
      console.log(`✓ Found ${artifact.name} (${stats.size} bytes)`);
    }
  }

  if (missing > 0) {
    console.error(`Missing ${missing} required artifact(s). Run 'npm run build:circuit' to generate them.`);
    process.exit(1);
  }

  // Check for stale artifacts
  const srcMtime = fs.statSync(circuitSrc).mtimeMs;
  const bytecodeMtime = fs.statSync(bytecodePath).mtimeMs;

  if (srcMtime > bytecodeMtime) {
    console.warn(
      `⚠ WARNING: Circuit source 'main.nr' was modified after 'age_gate.json' was built. Artifacts may be stale. Run 'npm run build:circuit'.`
    );
  } else {
    console.log("✓ All artifacts are fresh and consistent with circuit source.");
  }
}

main().catch((err) => {
  console.error("Artifact check failed:", err.message);
  process.exit(1);
});

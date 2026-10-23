import { spawnSync } from "child_process";
import { runTestSuite } from "../circuits-test/age_gate.test";

async function main() {
  console.log("=================================================");
  console.log(" Step 1: Running Nargo Circuit Unit Tests");
  console.log("=================================================\n");

  const wslCmd = 'export PATH="$HOME/.nargo/bin:$PATH"; cd /mnt/c/Users/nikita/OneDrive/Desktop/dev3/circuits/age_gate && nargo test';
  const res = spawnSync("wsl", ["-e", "bash", "-c", wslCmd], {
    stdio: "inherit",
    encoding: "utf-8",
  });

  if (res.status !== 0) {
    console.error("Nargo test suite failed!");
    process.exit(res.status || 1);
  }

  console.log("\n✓ Nargo circuit tests passed successfully.\n");

  console.log("=================================================");
  console.log(" Step 2: Running TypeScript Prover Integration");
  console.log("=================================================\n");

  await runTestSuite();
}

main().catch((err) => {
  console.error("Circuit test runner encountered fatal error:", err);
  process.exit(1);
});

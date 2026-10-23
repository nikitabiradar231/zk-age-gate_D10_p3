import { spawnSync } from "child_process";
import * as fs from "fs";
import * as path from "path";

function runWslCommand(bashScript: string) {
  const fullScript = `export PATH="$HOME/.local/bin:$HOME/.bb:$HOME/.nargo/bin:$PATH"; ${bashScript}`;
  const res = spawnSync("wsl", ["-e", "bash", "-c", fullScript], {
    stdio: "inherit",
  });
  if (res.status !== 0) {
    throw new Error(`WSL command failed with exit code ${res.status}`);
  }
}

function runForgeCommand(args: string[]) {
  const isWindows = process.platform === "win32";
  const forgeBin = isWindows
    ? "C:\\Users\\nikita\\.foundry\\bin\\forge.exe"
    : "forge";
  const res = spawnSync(forgeBin, args, { stdio: "inherit" });
  if (res.status !== 0) {
    throw new Error(`Forge command failed with exit code ${res.status}`);
  }
}

/**
 * Builds the Noir age_gate circuit, generates verification keys with Barretenberg,
 * generates the Solidity verifier, and post-processes it for integration.
 */
async function main() {
  console.log("=== Building zk-age-gate Circuit & Verifier ===");

  const rootDir = path.resolve(__dirname, "..");
  const targetDir = path.join(rootDir, "target");
  const vkDir = path.join(targetDir, "vk");
  const generatedDir = path.join(rootDir, "contracts", "generated");
  const verifierPath = path.join(generatedDir, "AgeGateVerifier.sol");

  fs.mkdirSync(targetDir, { recursive: true });
  fs.mkdirSync(vkDir, { recursive: true });
  fs.mkdirSync(generatedDir, { recursive: true });

  // 1. Compile Circuit
  console.log("1. Compiling Noir circuit with Nargo...");
  runWslCommand("cd /mnt/c/Users/nikita/OneDrive/Desktop/dev3 && nargo compile");

  // 2. Write Verification Key with Barretenberg (using keccak oracle hash for EVM verifier)
  console.log("2. Writing UltraHonk verification key with Barretenberg (keccak oracle)...");
  runWslCommand("cd /mnt/c/Users/nikita/OneDrive/Desktop/dev3 && bb write_vk -b ./target/age_gate.json -o ./target/vk --oracle_hash keccak");

  // 3. Generate Solidity Verifier
  console.log("3. Generating Solidity UltraVerifier with Barretenberg...");
  runWslCommand("cd /mnt/c/Users/nikita/OneDrive/Desktop/dev3 && bb write_solidity_verifier -k ./target/vk/vk -o ./contracts/generated/AgeGateVerifier.sol");

  // 4. Post-process AgeGateVerifier.sol
  console.log("4. Post-processing generated AgeGateVerifier.sol...");
  let solCode = fs.readFileSync(verifierPath, "utf-8");

  // Ensure BaseHonkVerifier.verify is marked virtual
  solCode = solCode.replace(
    "function verify(bytes calldata proof, bytes32[] calldata publicInputs) public view override returns (bool)",
    "function verify(bytes calldata proof, bytes32[] calldata publicInputs) public view virtual override returns (bool)"
  );

  // Append AgeGateVerifier wrapper implementing IAgeVerifier
  const ageGateVerifierExtension = `

import "../interfaces/IAgeVerifier.sol";

contract AgeGateVerifier is HonkVerifier, IAgeVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs)
        public
        view
        override(BaseHonkVerifier, IAgeVerifier)
        returns (bool)
    {
        return super.verify(proof, publicInputs);
    }
}
`;

  if (!solCode.includes("contract AgeGateVerifier")) {
    solCode += ageGateVerifierExtension;
  }

  fs.writeFileSync(verifierPath, solCode, "utf-8");
  console.log("✓ AgeGateVerifier.sol post-processed successfully.");

  // 5. Verify compilation with Foundry
  console.log("5. Verifying Solidity compilation with Foundry...");
  runForgeCommand(["compile"]);

  console.log("=== Build Circuit Completed Successfully! ===");
}

main().catch((err) => {
  console.error("Build failed:", err);
  process.exit(1);
});

import { spawnSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import { ethers } from "ethers";
import { AgeCredential, ClaimRequest, ProofOutput } from "./types";
import { verifyCredentialSignature } from "./credential";
import { buildProverInputs, formatProverToml } from "./inputs";

function runWslCommand(bashScript: string, silenceLogs = true) {
  const fullScript = `export PATH="$HOME/.local/bin:$HOME/.bb:$HOME/.nargo/bin:$PATH"; ${bashScript}`;
  const res = spawnSync("wsl", ["-e", "bash", "-c", fullScript], {
    stdio: silenceLogs ? "pipe" : "inherit",
    encoding: "utf-8",
  });
  if (res.status !== 0) {
    const errorMsg = res.stderr || res.stdout || `WSL command failed with exit code ${res.status}`;
    throw new Error(errorMsg);
  }
  return res.stdout;
}

/**
 * Generates a zero-knowledge age proof locally on the buyer's device.
 * Enforces that no private witness fields (birth date, credential secret, signature)
 * are ever logged, persisted, or returned in public outputs.
 */
export async function generateAgeProof(
  credential: AgeCredential,
  request: ClaimRequest,
  options: { verifyLocally?: boolean; verbose?: boolean } = {}
): Promise<ProofOutput> {
  // 1. Off-chain authenticity check: verify door partner signature
  if (!verifyCredentialSignature(credential)) {
    throw new Error("Invalid credential: Door partner signature verification failed.");
  }

  // 2. Prepare circuit inputs and client-side validations
  const prepared = buildProverInputs(credential, request);

  const rootDir = path.resolve(__dirname, "..", "..");
  const circuitDir = path.join(rootDir, "circuits", "age_gate");
  const targetDir = path.join(rootDir, "target");

  if (!fs.existsSync(path.join(targetDir, "age_gate.json"))) {
    throw new Error("Circuit bytecode not found. Please run 'npm run build:circuit' first.");
  }

  // 3. Create isolated ephemeral directory for local witness execution
  const runId = crypto.randomBytes(8).toString("hex");
  const tempDir = path.join(targetDir, `run_${runId}`);
  fs.mkdirSync(tempDir, { recursive: true });

  const proverTomlPath = path.join(circuitDir, "Prover.toml");
  const witnessPath = path.join(tempDir, "witness.gz");
  const proofDir = path.join(tempDir, "proof_out");
  fs.mkdirSync(proofDir, { recursive: true });

  try {
    // Write ephemeral Prover.toml (ignored by git and deleted after proving)
    const tomlContent = formatProverToml(prepared);
    fs.writeFileSync(proverTomlPath, tomlContent, "utf-8");

    // 4. Generate local witness with Nargo
    // Convert Windows path to WSL path
    const wslTempDir = `/mnt/c/Users/nikita/OneDrive/Desktop/dev3/target/run_${runId}`;
    const nargoCmd = `cd /mnt/c/Users/nikita/OneDrive/Desktop/dev3/circuits/age_gate && nargo execute ${wslTempDir}/witness`;
    runWslCommand(nargoCmd, !options.verbose);

    // 5. Generate UltraHonk proof with Barretenberg using Keccak random oracle for Solidity compatibility
    const bbProveCmd = `bb prove -b /mnt/c/Users/nikita/OneDrive/Desktop/dev3/target/age_gate.json -w ${wslTempDir}/witness.gz -o ${wslTempDir}/proof_out --oracle_hash keccak`;
    runWslCommand(bbProveCmd, !options.verbose);

    // Read generated proof file
    const proofFilePath = path.join(proofDir, "proof");
    if (!fs.existsSync(proofFilePath)) {
      throw new Error(`Proof file was not generated at expected path: ${proofFilePath}`);
    }
    const rawProofBytes = fs.readFileSync(proofFilePath);
    // Barretenberg standalone proof format: [uint32 total_fields] [public_inputs: 9 * 32 bytes] [proof_body: 14080 bytes]
    // The Solidity verifier expects strictly the 14080-byte proof_body (PROOF_SIZE 440 * 32)
    const proofOffset = rawProofBytes.length > 14080 ? rawProofBytes.length - 14080 : 0;
    const proofBytes = rawProofBytes.subarray(proofOffset);
    const proofHex = ethers.hexlify(proofBytes);

    // 6. Optional local verification with Barretenberg
    if (options.verifyLocally) {
      const vkFilePath = "/mnt/c/Users/nikita/OneDrive/Desktop/dev3/target/vk/vk";
      const bbVerifyCmd = `bb verify -k ${vkFilePath} -p ${wslTempDir}/proof_out/proof --oracle_hash keccak`;
      runWslCommand(bbVerifyCmd, !options.verbose);
      if (options.verbose) {
        console.log("✓ Barretenberg local proof verification succeeded.");
      }
    }

    return {
      proofHex,
      publicInputs: prepared.solidityPublicInputs,
      nullifierHex: prepared.solidityPublicInputs[8],
      claimant: request.claimantAddress,
      claimTimestamp: prepared.publicInputs.claimTimestamp,
      referenceDate: {
        year: prepared.publicInputs.refYear,
        month: prepared.publicInputs.refMonth,
        day: prepared.publicInputs.refDay,
      },
    };
  } finally {
    // Ephemeral cleanup: wipe private witness and temp files
    try {
      if (fs.existsSync(proverTomlPath)) {
        fs.unlinkSync(proverTomlPath);
      }
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup error
    }
  }
}

/**
 * Verifies a proof locally against the generated verification key using Barretenberg.
 */
export async function verifyProofWithBarretenberg(
  proofHex: string,
  publicInputs?: string[]
): Promise<boolean> {
  const rootDir = path.resolve(__dirname, "..", "..");
  const targetDir = path.join(rootDir, "target");
  const vkPath = "/mnt/c/Users/nikita/OneDrive/Desktop/dev3/target/vk/vk";

  const runId = crypto.randomBytes(8).toString("hex");
  const tempProofPath = path.join(targetDir, `verify_${runId}.proof`);

  try {
    const proofBytes = ethers.getBytes(proofHex);
    let fullProofBytes: Uint8Array = proofBytes;

    // If given the Solidity 14080-byte proof body and public inputs, reconstitute the bb CLI proof format
    if (proofBytes.length === 14080 && publicInputs && publicInputs.length === 9) {
      const header = Buffer.alloc(4);
      header.writeUInt32BE(449, 0); // 440 proof elements + 9 public inputs
      const pubBytesList = publicInputs.map((p) => ethers.getBytes(p));
      fullProofBytes = Buffer.concat([header, ...pubBytesList, Buffer.from(proofBytes)]);
    }

    fs.writeFileSync(tempProofPath, fullProofBytes);

    const wslProofPath = `/mnt/c/Users/nikita/OneDrive/Desktop/dev3/target/verify_${runId}.proof`;
    const bbVerifyCmd = `bb verify -k ${vkPath} -p ${wslProofPath} --oracle_hash keccak`;
    runWslCommand(bbVerifyCmd, true);
    return true;
  } catch (err) {
    return false;
  } finally {
    if (fs.existsSync(tempProofPath)) {
      fs.unlinkSync(tempProofPath);
    }
  }
}

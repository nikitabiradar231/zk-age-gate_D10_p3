import { execSync } from "child_process";
import * as fs from "fs";
import * as path from "path";

/**
 * Secret scanner for zk-age-gate.
 * Scans all Git-tracked files for potential private keys, mnemonics, tokens, or credentials.
 * Fails if any untracked or tracked sensitive patterns are detected.
 */

// Patterns indicating potential secrets
const SECRET_PATTERNS: { name: string; regex: RegExp; allowedIn?: string[] }[] = [
  {
    name: "Private Key (RSA / EC / OpenSSH)",
    regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
  },
  {
    name: "Generic Private Key Hex (unallowed)",
    // 64-character hex string preceded by private_key or secret, excluding documented test constants
    regex: /(?:private_?key|priv_?key|secret_?key)\s*[:=]\s*["'](?!0x00|c87702da708451dd58b33919ac97d41a43e4d51315847fa30e41865d63718810)[0-9a-fA-F]{64}["']/i,
    allowedIn: ["scripts/check-no-secrets.ts"],
  },
  {
    name: "Ethereum Seed Phrase / Mnemonic (12+ words)",
    regex: /(?:mnemonic|seed_phrase)\s*[:=]\s*["'][a-z]+(\s+[a-z]+){11,}["']/i,
  },
  {
    name: "AWS Access Key ID",
    regex: /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/,
  },
  {
    name: "GitHub Personal Access Token",
    regex: /gh[pousr]_[A-Za-z0-9_]{36,255}/,
  },
  {
    name: "Alchemy / Infura Authenticated RPC with secret",
    regex: /https:\/\/(?:eth-mainnet|mainnet|sepolia)\.(?:alchemyapi\.io|infura\.io)\/v[0-9]\/[a-zA-Z0-9_-]{32}/,
  },
];

// Ignored files (e.g. documentation placeholders, vendor libraries, package-lock)
const IGNORED_PATHS = [
  "package-lock.json",
  ".gitignore",
  "Nargo.lock",
  "lib/",
];

async function main() {
  console.log("=== zk-age-gate: Secret Scanner ===");

  // 1. Get all git-tracked files
  let trackedFiles: string[] = [];
  try {
    const gitOutput = execSync("git ls-files", { encoding: "utf-8" });
    trackedFiles = gitOutput
      .split("\n")
      .map((f) => f.trim())
      .filter((f) => f.length > 0);
  } catch (err) {
    console.warn("Git not available or not in a git repo.");
  }

  // If no files are tracked yet, inspect working directory files
  if (trackedFiles.length === 0) {
    try {
      const gitStatus = execSync("git status --porcelain -uall", { encoding: "utf-8" });
      const candidateFiles = gitStatus
        .split("\n")
        .map((line) => line.slice(3).trim())
        .filter((f) => f.length > 0 && fs.existsSync(f) && fs.statSync(f).isFile());
      trackedFiles = candidateFiles;
    } catch {}
  }

  // 2. Check that sensitive files are NOT tracked in Git
  const forbiddenFiles = [
    ".env",
    ".env.local",
    "circuits/age_gate/Prover.toml",
    "target/witness.gz",
  ];

  let violations = 0;

  for (const forbidden of forbiddenFiles) {
    if (trackedFiles.includes(forbidden)) {
      console.error(`✗ VIOLATION: Sensitive file is tracked in Git index: ${forbidden}`);
      violations++;
    }
  }

  // 3. Scan tracked file contents
  for (const relativePath of trackedFiles) {
    if (
      IGNORED_PATHS.some(
        (ignored) =>
          relativePath.startsWith(ignored) ||
          relativePath.endsWith(ignored) ||
          relativePath.includes(ignored)
      )
    ) {
      continue;
    }

    if (!fs.existsSync(relativePath)) {
      continue;
    }

    // Skip binary files
    if (
      relativePath.endsWith(".gz") ||
      relativePath.endsWith(".png") ||
      relativePath.endsWith(".jpg") ||
      relativePath.endsWith(".ico")
    ) {
      continue;
    }

    const content = fs.readFileSync(relativePath, "utf-8");

    for (const pattern of SECRET_PATTERNS) {
      if (pattern.allowedIn && pattern.allowedIn.some((allowed) => relativePath.includes(allowed))) {
        continue;
      }

      if (pattern.regex.test(content)) {
        console.error(
          `✗ VIOLATION: Detected pattern '${pattern.name}' in tracked file: ${relativePath}`
        );
        violations++;
      }
    }
  }

  if (violations > 0) {
    console.error(`\nFound ${violations} secret scanning violation(s)! Build failed.`);
    process.exit(1);
  }

  console.log(`✓ Scanned ${trackedFiles.length} tracked files. No secrets found!`);
}

main().catch((err) => {
  console.error("Secret scan failed:", err.message);
  process.exit(1);
});

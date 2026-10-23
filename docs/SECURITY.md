# Security Policy & Operational Hardening: `zk-age-gate`

## 1. Overview & Disclaimer

This repository is built for **Road to Devcon X — Problem 3 (`zk-gated-age-proof`)**.

> [!CAUTION]
> **Production Notice**: While this implementation uses real zero-knowledge circuits (Noir), genuine cryptographic proving (Barretenberg UltraHonk), and real on-chain EVM verification (Solidity `AgeGateVerifier`), a local testnet demonstration is NOT equivalent to an audited production deployment.

---

## 2. Distinction: Local Demonstration vs. Production Deployment

| Feature | Local Demonstration (`zk-age-gate`) | Production Hardened Deployment |
| :--- | :--- | :--- |
| **Door Partner Key** | Deterministic synthetic key (`TEST_ISSUER_PRIVATE_KEY_HEX`) | FIPS 140-3 Level 3 Hardware Security Module (HSM) |
| **Revocation Registry** | Credential expiration check | Dynamic cryptographic accumulator (Sparse Merkle Tree on-chain) |
| **Audit Status** | Comprehensive internal test suite (50+ tests) | Independent third-party smart contract & ZK circuit audits |
| **Client Proving** | Node.js / CLI / Native Barretenberg binary | WebAssembly (Wasm) NoirJS + Barretenberg WebWorker in browser |
| **Key Ceremony** | Pre-generated Aztec BN254 SRS | Multi-party trusted setup verification check |
| **Gas Optimization** | Standard UltraHonk verifier (~2.8M gas) | Recursive SNARK folding (Honk-to-Client-IVC) for <300k gas |

---

## 3. Production Hardening Checklist

Before deploying this contract to an Ethereum mainnet or L2 environment:

1. **Secure Key Management (Door Partner)**:
   - Ensure the door partner's private key never touches unencrypted storage or network-accessible servers.
   - Use multi-signature authorization or hardware-backed signing endpoints (e.g. AWS KMS, CloudHSM) with strict rate-limiting and audit logging.
2. **Contract Ownership & Governance**:
   - Transfer `AgeGate` ownership to a multi-signature wallet (e.g. Safe) or a timelock controller.
   - Restrict `setAuthorizedIssuer` behind a timelock delay to allow users to review key updates.
3. **Mempool Privacy & Front-Running**:
   - While proof theft is prevented by account binding (`claimant = msg.sender`), transaction metadata is visible in public mempools.
   - Encourage users to broadcast transactions through private RPC endpoints (e.g. Flashbots Protect, MEV-Blocker) to prevent MEV searchers from analyzing claim transactions.
4. **Wasm Proving in Browser**:
   - Integrate NoirJS and Barretenberg Wasm into the festival frontend.
   - Ensure Web Workers handle multithreaded proving without blocking the main browser thread.
5. **Secret Scanner in CI/CD**:
   - Enforce automated secret scanning (`npm run check:no-secrets`) on all pull requests and merges.

---

## 4. Responsible Testing Policy

- **No Real Secrets**: Developers and contributors must never commit real private keys, mnemonics, or production API tokens.
- **No Mock Bypasses**: Integration tests must execute against real compiled circuit artifacts and real Barretenberg proofs. Mocks are restricted solely to isolated negative unit tests (e.g., verifying contract behavior when a verifier reverts).
- **Ephemeral Prover Inputs**: Test scripts must automatically delete temporary prover files and witness artifacts after proving.

---

## 5. Vulnerability Disclosure

If you discover a security vulnerability in `zk-age-gate`:
1. **Do not** file a public GitHub issue.
2. Email security findings to `security@slowbloomfestival.example` with detailed reproduction steps.
3. Allow up to 48 hours for acknowledgment and coordination prior to public disclosure.

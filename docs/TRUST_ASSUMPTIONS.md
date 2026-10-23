# Trust Assumptions & Cryptographic Architecture: `zk-age-gate`

## 1. Overview

A fundamental maxim in applied zero-knowledge systems is:
> **A zero-knowledge proof proves only that a statement is mathematically satisfied by the supplied inputs. It does NOT prove that self-asserted input data represents an authentic real-world fact.**

If a buyer could submit an arbitrary birth date into a zero-knowledge circuit, a 14-year-old could simply input `birth_year = 2000` and generate a mathematically valid proof. 

To bridge this semantic gap, `zk-age-gate` establishes an explicit **trust boundary** anchored by an authorized door partner (identity verification authority).

---

## 2. The Door Partner Trust Model

### 2.1 Off-Chain Identity Verification
1. The buyer presents a government-issued photo identity document (passport, national identity card, or driver's license) to the authorized Slow Bloom door partner.
2. The door partner inspects security features (holograms, microprint, MRZ barcode, NFC chip) to verify authenticity.
3. The door partner issues an off-chain digital credential containing:
   - `credential_id` (32 bytes unique serial)
   - `birth_year`, `birth_month`, `birth_day`
   - `expiry_year`, `expiry_month`, `expiry_day`
   - `buyer_id_commitment` (16 bytes derived from the buyer's private secret)
4. The door partner signs the 56-byte credential hash using their ECDSA secp256k1 private key.

### 2.2 What the Festival Must Trust
The Slow Bloom festival trusts that:
1. The door partner does not collude with underage individuals to issue false credentials.
2. The door partner's private signing key is stored in a secure Hardware Security Module (HSM) or enclave.
3. The door partner executes physical ID inspections with rigorous standards.

---

## 3. Cryptographic Verification Inside Noir

Rather than relying on the buyer to relay an unverified date of birth, the Noir circuit (`circuits/age_gate/src/main.nr`) verifies the door partner's signature **inside the SNARK**:

1. **ECDSA secp256k1 Verification**:
   The circuit executes `std::ecdsa_secp256k1::verify_signature(issuer_pub_x, issuer_pub_y, issuer_signature, credential_hash)`.
2. **Authorized Issuer Key Pinning**:
   The circuit computes `compute_issuer_pubkey_hash(issuer_pub_x, issuer_pub_y)` and asserts equality with `issuer_pubkey_hash`.
3. **Contract Authorization**:
   The smart contract (`AgeGate.sol`) pins `authorizedIssuerPubKeyHash`. Prover-submitted public inputs that fail to match this commitment cause verifier failure.

---

## 4. Key Management & Rotation

- **Contract-Controlled Configuration**:
  The smart contract owner can update `authorizedIssuerPubKeyHash` via `setAuthorizedIssuer(bytes32 newIssuerHash)` to rotate door partner keys.
- **Cost of Rotation**:
  Because the issuer public key is committed via a public input hash rather than hardcoded in circuit bytecode, rotating the door partner key **does not require recompiling the circuit or deploying a new verification key**.
- **Historical Claims**:
  Nullifiers already consumed under a previous issuer key remain consumed in contract storage, preserving replay protection across key rotations.

---

## 5. Credential Expiry & Revocation Limitations

### 5.1 Expiry Policy
- Each credential includes an `expiry_year`, `expiry_month`, and `expiry_day`.
- The circuit enforces:
  ```rust
  assert(is_on_or_before(ref_year, ref_month, ref_day, expiry_year, expiry_month, expiry_day));
  ```
- If the reference date is past the credential expiry date, proof generation fails.

### 5.2 Revocation Limitations
- **Current Limitation**: In the current implementation, immediate off-chain revocation (e.g. for stolen identity documents prior to expiration) is not tracked via an on-chain dynamic accumulator (such as an incremental Merkle tree or dynamic cryptographic blacklist).
- **Mitigation & Future Work**: Production deployments requiring real-time revocation should incorporate a Merkle inclusion proof against a door partner revocation tree or an on-chain sparse nullifier registry.

---

## 6. Proving System & Toolchain Assumptions

### 6.1 Toolchain Versions
- **Noir / Nargo**: `v1.0.0-beta.3`
- **Barretenberg (`bb`)**: `v0.82.2` (Patched UltraHonk soundness release)
- **Solidity**: `0.8.28` (via Foundry Forge `v1.8.1` / `v1.8.6`)
- **Node.js**: `v24.11.0` LTS

### 6.2 UltraHonk SNARK Assumptions
- **Proof System**: Barretenberg UltraHonk, an un-opinionated, ultra-fast Plonk-derived proving system utilizing sumcheck protocols, multilinear polynomial commitments, and logarithmic lookup arguments.
- **Elliptic Curve**: BN254 (alt_bn128), supported natively on Ethereum via precompiles (`ecAdd`, `ecMul`, `ecPairing` at addresses 0x06, 0x07, 0x08).
- **Structured Reference String (SRS)**: The KZG polynomial commitment scheme relies on the multi-party computation (MPC) trusted setup conducted for Aztec and Ethereum ignition ceremonies. The unforgeability of proofs depends on at least one honest participant having destroyed their toxic waste during the ceremony.
- **Random Oracle**: The generated verifier uses `keccak256` for Fiat-Shamir challenges, matching EVM native hashing efficiency.

---

## 7. Date & Time Semantics

### 7.1 Civil Calendar Consistency
- **No Fractional Approximations**: The system explicitly avoids dividing Unix timestamps by 365 or 365.25 days, which introduces boundary errors around leap days and birthdays.
- **Gregorian Calendar Rules**:
  - A year is a leap year if divisible by 4 and not 100, or if divisible by 400.
  - Leap-day babies (born February 29) legally complete their 18th year on March 1st in non-leap years.
- **On-Chain Date Derivation**:
  `AgeGate.sol` derives the reference date directly from `block.timestamp` using the civil calendar algorithm by Howard Hinnant. Both the Noir circuit and the Solidity contract share identical date computation semantics.

### 7.2 UTC Day Boundaries
The reference date rolls over at `00:00:00 UTC`. A buyer turning 18 on October 24 becomes eligible precisely at midnight UTC on October 24.

# Privacy Architecture & Guarantees: `zk-age-gate`

## 1. Executive Summary

The **zk-age-gate** system guarantees that a buyer can prove they have reached their 18th birthday on the festival's authorized reference date without disclosing their exact birth date, birth month, birth year, age, or identity documents to the Slow Bloom festival, the smart contract, or public blockchain observers.

Zero-knowledge cryptography (Noir + Barretenberg UltraHonk) is combined with an off-chain door partner credential scheme to ensure that only authentic age attestations can be used to generate valid proofs.

---

## 2. Data Classification Matrix

| Data Item | Storage Location | Circuit Witness Status | Public On-Chain? | Disclosed to Festival? |
| :--- | :--- | :--- | :--- | :--- |
| **Physical ID (Passport / License)** | Physical document checked at door | Not in circuit | **NO** | Only inspected off-chain by door partner |
| **Exact Birth Date (`YYYY-MM-DD`)** | Local device memory | **Private Witness** | **NO** | **NO** |
| **Buyer Secret Salt (32 bytes)** | Local device storage / wallet | **Private Witness** | **NO** | **NO** |
| **Credential ID (32 bytes)** | Local device storage | **Private Witness** | **NO** | **NO** |
| **Door Partner ECDSA Signature** | Local device storage | **Private Witness** | **NO** | **NO** |
| **Credential Expiry Date** | Local device storage | **Private Witness** | **NO** | **NO** |
| **Claimant Address (`msg.sender`)** | Blockchain transaction | **Public Input** | **YES** | **YES** |
| **Festival Context (`FESTIVAL_CONTEXT`)** | Smart contract constant | **Public Input** | **YES** | **YES** |
| **Pass Type (`PASS_TYPE_LATE_NIGHT`)** | Smart contract constant | **Public Input** | **YES** | **YES** |
| **Reference Date (`YYYY-MM-DD`)** | Derived from `block.timestamp` | **Public Input** | **YES** | **YES** |
| **Claim Timestamp** | Transaction calldata | **Public Input** | **YES** | **YES** |
| **Issuer Public Key Hash** | Contract configuration | **Public Input** | **YES** | **YES** |
| **Nullifier** | Contract storage & event | **Public Input** | **YES** | **YES** |
| **UltraHonk Proof (14,080 bytes)** | Transaction calldata | SNARK Proof Body | **YES** | **YES** |

---

## 3. What Stays on the Buyer's Device

The buyer's device (browser or local client CLI) acts as an isolated zero-knowledge prover:

1. **Exact Birth Date**:
   The birth year, month, and day are supplied only as private witness elements to the local Noir circuit execution.
2. **Door Partner Signature & Credential ID**:
   The 64-byte ECDSA secp256k1 signature and 32-byte credential ID remain strictly local.
3. **Buyer Secret Salt**:
   A 256-bit cryptographically secure pseudorandom scalar generated on the buyer's device. The lowest 16 bytes are committed into the credential payload (`buyer_id_commitment`), while the full 32 bytes act as the salt for nullifier generation.
4. **Local Cleanup**:
   Ephemeral witness files and input TOML configurations are automatically wiped from disk immediately after proof generation.

---

## 4. What Values Become Public Inputs

The circuit and Solidity verifier (`AgeGateVerifier.sol`) expose exactly 9 public inputs:

1. `claimant`: Ethereum address of the claiming account (`msg.sender`), preventing mempool front-running and proof theft.
2. `festival_context`: `0x534c4f575f424c4f4f4d5f464553544956414c5f323032360000000000000000` (ASCII `"SLOW_BLOOM_FESTIVAL_2026"`), domain-separating proofs across festivals.
3. `pass_type`: `1` (`LATE_NIGHT_PASS`), preventing cross-pass replay.
4. `ref_year`: Contract-authorized reference year (e.g. `2026`).
5. `ref_month`: Contract-authorized reference month (e.g. `10`).
6. `ref_day`: Contract-authorized reference day (e.g. `24`).
7. `claim_timestamp`: The UTC Unix timestamp of the claim, validated to be within a 1-hour window of `block.timestamp`.
8. `issuer_pubkey_hash`: The BN254 field commitment of the door partner's secp256k1 public key.
9. `nullifier`: Deterministic BN254 field element derived from `keccak256(credential_id || buyer_secret || festival_context || pass_type)`.

---

## 5. Why the Birth Date is Not Disclosed

The circuit enforces two mathematical statements using Barretenberg UltraHonk:
1. `is_on_or_after(ref_year, ref_month, ref_day, 18th_birthday) == true`
2. `verify_signature(issuer_pub_x, issuer_pub_y, signature, credential_hash) == true`

Under the zero-knowledge property of UltraHonk (randomized polynomial masking and blinding factors), the resulting proof and commitment polynomials reveal **zero Shannon information** about the private witness inputs. Observers cannot distinguish whether the buyer is 18 years old, 25 years old, or 80 years old, nor can they determine which calendar day the buyer was born.

---

## 6. What Observers Can Infer

While birth date and identity are concealed, public blockchain visibility permits observers to infer:

1. **Eligibility**: The account submitting the transaction is at least 18 years old on the contract reference date.
2. **Authenticity**: The claimant possesses a valid, unrevoked, unexpired credential issued by the authorized door partner.
3. **Festival Participation**: The account holds a Slow Bloom Late-Night Festival Pass entitlement.
4. **Timing**: The exact block timestamp and block number at which the pass was claimed.

---

## 7. Blockchain Linkability & Anonymity Limitations

> [!WARNING]
> Zero-knowledge proofs do **not** provide absolute anonymity on a public ledger.

1. **Wallet Address Linkability**:
   The claim transaction is signed by `msg.sender`. If `msg.sender` is an address linked to a public ENS name, a centralized exchange KYC withdrawal, or social identity, observers will associate that real-world identity with the late-night pass.
2. **Network Layer (IP) Linkability**:
   Submitting transactions through centralized RPC providers (Infura, Alchemy) or broadcasting via public mempools leaks client IP addresses unless privacy-preserving relays, VPNs, or Tor are utilized.
3. **Transaction Fee Origins**:
   The ETH used to pay transaction gas links the claiming account to the funding source. Users requiring financial unlikability should fund claiming accounts via privacy pools or stealth address protocols.

---

## 8. Client-Side Threat Vectors

The privacy of the buyer also relies on local device hygiene:

1. **Malicious Browser Extensions**: Extensions with broad DOM and memory read permissions could theoretically inspect credential inputs prior to proving.
2. **Local Logs & History**: Proof generation scripts must never log private witness fields. `zk-age-gate` explicitly silences witness logging.
3. **Issuer Records**: The door partner (identity verification partner) necessarily inspects government IDs during credential issuance. If the door partner keeps logs linking `credential_id` to the physical ID, legal subpoenas or issuer data breaches could correlate `credential_id` with real identities. To mitigate this, `credential_id` is kept private in the circuit and never published on-chain.

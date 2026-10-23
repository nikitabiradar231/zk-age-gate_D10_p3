# Threat Model & Attack Vector Analysis: `zk-age-gate`

## 1. System Scope & Objective

The primary objective of `zk-age-gate` is to ensure that only authenticated individuals who are 18 years or older on the contract-authorized reference date can claim a Slow Bloom late-night festival pass, while preventing identity theft, double claiming, front-running, and birth-date disclosure.

---

## 2. Threat Vector Matrix

| Threat Category | Attack Description | Severity | Mitigation in `zk-age-gate` | Verification Evidence |
| :--- | :--- | :--- | :--- | :--- |
| **Fake Birth Dates** | User supplies arbitrary birth date to prove 18+ | Critical | Birth date must be signed by door partner; signature verified in circuit | Tested in `main.nr` & `age_gate.test.ts` |
| **Forged Credentials** | Attacker creates fake credential using unauthorized key | Critical | Contract pins `authorizedIssuerPubKeyHash`; circuit verifies key matches hash | Tested in `AgeGateVerifier.t.sol` |
| **Altered Credentials** | Attacker changes birth date on legitimate credential | Critical | Any bit alteration in birth date invalidates ECDSA secp256k1 signature | Tested in `age_gate.test.ts` |
| **Underage Claimants** | 16-year-old attempts to generate proof | High | Circuit enforces `ref_date >= 18th_birthday`; prover fails constraint | Tested in `AgeGateTest` & `main.nr` |
| **Proof Theft / Copying** | Attacker copies valid proof from public mempool | Critical | Proof is bound to `claimant = msg.sender`; contract checks `publicInputs[0]` | Tested in `AgeGate.t.sol` (`test_ProofStolenByAnotherAccountFails`) |
| **Front-Running** | Searcher attempts to preempt claimant's transaction | High | Proof verification fails when executed by searcher's account (`msg.sender != claimant`) | Tested in `AgeGate.t.sol` |
| **Replay Attacks** | User submits the same proof twice to claim multiple passes | High | Contract consumes unique nullifier in storage; second claim reverts with `NullifierAlreadyConsumed` | Tested in `AgeGate.t.sol` (`test_ConsumedNullifierCannotBeReused`) |
| **Stale Proofs** | Attacker submits proof generated weeks prior | Medium | Contract checks `claim_timestamp <= block.timestamp` and `block.timestamp - claim_timestamp <= 3600` | Tested in `AgeGate.t.sol` (`test_StaleProofIsRejected`) |
| **Future Timestamps** | Attacker submits timestamp in the future | Medium | Contract reverts with `FutureClaimTimestamp` if `claimTimestamp > block.timestamp` | Tested in `AgeGate.t.sol` (`test_FutureClaimTimestampIsRejected`) |
| **Public Input Mismatch** | Attacker changes calldata public inputs to bypass checks | Critical | UltraHonk verifier checks public inputs against cryptographic proof commitments | Tested in `AgeGateVerifier.t.sol` |
| **Noncanonical Encoding** | Attacker provides unreduced field elements | Medium | Circuit and contract check field range (`val < BN254_MODULUS`) | Tested in `test/ts-runner.ts` |
| **Contract Bypass** | Attacker calls internal or helper functions to claim pass | Critical | Only `claimLateNightPass` grants access; verified by real verifier call | Tested in `AgeGate.t.sol` (`test_NoAlternateAccessPath`) |
| **Verifier Revert / Error** | Verifier reverts or returns false but access is granted | Critical | Contract requires verifier to return `true`; reverts otherwise | Tested in `AgeGate.t.sol` (`test_MockFailingVerifierNeverGrantsAccess`) |
| **Issuer Key Compromise** | Door partner private key is leaked | Critical | Contract owner calls `setAuthorizedIssuer` to revoke compromised key | Tested in `AgeGate.t.sol` (`test_OnlyOwnerCanModifyAdminSettings`) |
| **Data Leakage in Logs** | Prover logs birth date or witness secrets | High | Prover code explicitly avoids logging sensitive fields; ephemeral files wiped | Tested in `test/ts-runner.ts` |
| **Denial of Service** | Malicious users exhaust pass supply without proof | Low | Passes are only allocated after proof verifies; cap cannot be griefed | Tested in `AgeGate.t.sol` (`test_MaxPassesExceededRejects`) |

---

## 3. Deep Dive: High-Risk Attack Scenarios

### 3.1 Proof Theft from the Mempool (Front-Running)
- **Scenario**: Alice generates a valid UltraHonk proof on her laptop and broadcasts a transaction with `claimant = Alice`. Eve runs a mempool monitoring bot, sees Alice's calldata, and submits the exact same proof with higher gas from `msg.sender = Eve`.
- **Mitigation**: 
  The smart contract constructs the claimant public input from `msg.sender`:
  ```solidity
  if (publicInputs[0] != bytes32(uint256(uint160(msg.sender)))) {
      revert ClaimantMismatch();
  }
  ```
  If Eve submits Alice's proof, `msg.sender` is Eve. If Eve keeps `publicInputs[0] = Alice`, the contract reverts with `ClaimantMismatch`. If Eve modifies `publicInputs[0] = Eve`, the UltraHonk verifier rejects the proof with `SumcheckFailed()` because the proof polynomial was evaluated for Alice's address.

### 3.2 Double Claiming & Sybil Attacks
- **Scenario**: Bob claims a late-night festival pass. He transfers the pass or attempts to claim a second pass using the same credential.
- **Mitigation**:
  1. **Account Binding**: `hasClaimed[msg.sender]` prevents repeated claims from the same wallet address.
  2. **Nullifier Enforcement**: Even if Bob uses a different wallet address, the circuit derives the nullifier deterministically:
     $$\text{nullifier} = \text{keccak256}(\text{credential\_id} \parallel \text{buyer\_secret} \parallel \text{festival\_context} \parallel \text{pass\_type}) \pmod{r}$$
     The contract records `consumedNullifiers[nullifier] = true`. Any subsequent claim with the same credential reverts with `NullifierAlreadyConsumed()`.

### 3.3 Reference Date Manipulation
- **Scenario**: A 17-year-old whose birthday is tomorrow attempts to pass a future reference date into the contract to prove they are 18.
- **Mitigation**:
  The smart contract derives the reference date directly from `block.timestamp` using the civil calendar algorithm:
  ```solidity
  (uint32 refYear, uint8 refMonth, uint8 refDay) = timestampToDate(block.timestamp);
  if (
      publicInputs[3] != bytes32(uint256(refYear)) ||
      publicInputs[4] != bytes32(uint256(refMonth)) ||
      publicInputs[5] != bytes32(uint256(refDay))
  ) {
      revert InvalidReferenceDate();
  }
  ```
  The claimant cannot provide a chosen reference date.

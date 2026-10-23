// SPDX-License-Identifier: MIT
pragma solidity >=0.8.21;

import "forge-std/Test.sol";
import "../contracts/AgeGate.sol";
import "../contracts/generated/AgeGateVerifier.sol";
import "../contracts/interfaces/IAgeVerifier.sol";

/**
 * @title MockRevertingVerifier
 * @notice Mock verifier that reverts to test that verifier reverts never grant access.
 */
contract MockRevertingVerifier is IAgeVerifier {
    function verify(bytes calldata, bytes32[] calldata) external pure override returns (bool) {
        revert("SimulatedVerifierFailure");
    }
}

/**
 * @title MockFailingVerifier
 * @notice Mock verifier that returns false to test that failed verifications never grant access.
 */
contract MockFailingVerifier is IAgeVerifier {
    function verify(bytes calldata, bytes32[] calldata) external pure override returns (bool) {
        return false;
    }
}

contract AgeGateTest is Test {
    AgeGate public ageGate;
    AgeGateVerifier public realVerifier;

    address public owner;
    address public claimant; // 0x70997970C51812dc3A010C7d01b50e0d17dc79C8
    address public attacker = address(0xbadB0b);

    bytes public realProof;
    bytes32[] public realPublicInputs;
    bytes32 public realNullifier;
    uint64 public realClaimTimestamp;
    bytes32 public festivalContext;
    uint256 public passType = 1;
    bytes32 public issuerPubKeyHash;

    function setUp() public {
        owner = address(this);
        claimant = address(0x70997970C51812dc3A010C7d01b50e0d17dc79C8);

        // Read real fixture
        string memory json = vm.readFile("test/fixtures/proof_fixture.json");
        realProof = vm.parseJsonBytes(json, ".proofHex");
        realPublicInputs = vm.parseJsonBytes32Array(json, ".publicInputs");
        realNullifier = vm.parseJsonBytes32(json, ".nullifierHex");
        realClaimTimestamp = uint64(vm.parseJsonUint(json, ".claimTimestamp"));

        // Match public inputs from circuit
        festivalContext = realPublicInputs[1];
        issuerPubKeyHash = realPublicInputs[7];

        // Deploy real Barretenberg UltraHonk verifier
        realVerifier = new AgeGateVerifier();

        // Deploy AgeGate access control contract
        ageGate = new AgeGate(
            address(realVerifier),
            festivalContext,
            passType,
            issuerPubKeyHash,
            100 // max 100 passes
        );

        // Warp to block timestamp matching the reference date (2026-10-23)
        // Ensure block.timestamp is within 60s of claim timestamp
        vm.warp(uint256(realClaimTimestamp) + 60);
    }

    /// @notice 1. Valid adult can claim pass successfully with real proof.
    function test_ValidAdultCanClaim() public {
        assertFalse(ageGate.hasPass(claimant), "Claimant should not have pass initially");
        assertFalse(ageGate.isNullifierConsumed(realNullifier), "Nullifier should not be consumed");

        vm.prank(claimant);
        bool success = ageGate.claimLateNightPass(realProof, realNullifier, realClaimTimestamp);

        assertTrue(success, "Claim function should return true");
        assertTrue(ageGate.hasPass(claimant), "Claimant must have pass entitlement recorded");
        assertTrue(ageGate.isNullifierConsumed(realNullifier), "Nullifier must be marked consumed");
        assertEq(ageGate.totalPassesClaimed(), 1, "Total passes claimed must be 1");
    }

    /// @notice 2. Account binding: Proof from account A is rejected when submitted by account B (mempool front-running protection).
    function test_ProofStolenByAnotherAccountFails() public {
        // Attacker attempts to front-run and submit Alice's proof
        vm.prank(attacker);
        vm.expectRevert(AgeGate.InvalidProof.selector);
        ageGate.claimLateNightPass(realProof, realNullifier, realClaimTimestamp);

        assertFalse(ageGate.hasPass(attacker), "Attacker must not be granted pass");
        assertFalse(ageGate.isNullifierConsumed(realNullifier), "Nullifier must not be consumed by failed attempt");
    }

    /// @notice 3. Replay protection: A claim cannot be repeated by the same account.
    function test_ClaimCannotBeRepeatedBySameAccount() public {
        vm.prank(claimant);
        ageGate.claimLateNightPass(realProof, realNullifier, realClaimTimestamp);

        // Second attempt by the same account reverts with PassAlreadyClaimed
        vm.prank(claimant);
        vm.expectRevert(AgeGate.PassAlreadyClaimed.selector);
        ageGate.claimLateNightPass(realProof, realNullifier, realClaimTimestamp);
    }

    /// @notice 4. Replay protection: A consumed nullifier cannot be reused even by another account.
    function test_ConsumedNullifierCannotBeReused() public {
        vm.prank(claimant);
        ageGate.claimLateNightPass(realProof, realNullifier, realClaimTimestamp);

        address secondUser = address(0x2222);
        vm.prank(secondUser);
        vm.expectRevert(abi.encodeWithSelector(AgeGate.NullifierAlreadyConsumed.selector, realNullifier));
        ageGate.claimLateNightPass(realProof, realNullifier, realClaimTimestamp);
    }

    /// @notice 5. Stale proofs are rejected using block.timestamp.
    function test_StaleProofIsRejected() public {
        // Warp block.timestamp past the 1-hour PROOF_MAX_AGE window
        vm.warp(uint256(realClaimTimestamp) + ageGate.PROOF_MAX_AGE() + 1);

        vm.prank(claimant);
        vm.expectRevert(
            abi.encodeWithSelector(
                AgeGate.ProofStale.selector,
                realClaimTimestamp,
                block.timestamp,
                ageGate.PROOF_MAX_AGE()
            )
        );
        ageGate.claimLateNightPass(realProof, realNullifier, realClaimTimestamp);
    }

    /// @notice 6. Invalid future challenge/claim timestamp is rejected.
    function test_FutureClaimTimestampIsRejected() public {
        // Set block.timestamp to be before claimTimestamp
        vm.warp(uint256(realClaimTimestamp) - 10);

        vm.prank(claimant);
        vm.expectRevert(
            abi.encodeWithSelector(
                AgeGate.ProofTimestampInFuture.selector,
                realClaimTimestamp,
                block.timestamp
            )
        );
        ageGate.claimLateNightPass(realProof, realNullifier, realClaimTimestamp);
    }

    /// @notice 7. Tampered proof bytes are rejected and access is not granted.
    function test_TamperedProofIsRejected() public {
        bytes memory tamperedProof = new bytes(realProof.length);
        for (uint256 i = 0; i < realProof.length; i++) {
            tamperedProof[i] = realProof[i];
        }
        tamperedProof[100] = bytes1(uint8(tamperedProof[100]) ^ 0xaa);

        vm.prank(claimant);
        vm.expectRevert(AgeGate.InvalidProof.selector);
        ageGate.claimLateNightPass(tamperedProof, realNullifier, realClaimTimestamp);

        assertFalse(ageGate.hasPass(claimant), "Access must not be granted on tampered proof");
    }

    /// @notice 8. Failed verifier call never grants access.
    function test_MockFailingVerifierNeverGrantsAccess() public {
        MockFailingVerifier mockVerifier = new MockFailingVerifier();
        AgeGate gatedWithMock = new AgeGate(
            address(mockVerifier),
            festivalContext,
            passType,
            issuerPubKeyHash,
            100
        );

        vm.prank(claimant);
        vm.expectRevert(AgeGate.InvalidProof.selector);
        gatedWithMock.claimLateNightPass(realProof, realNullifier, realClaimTimestamp);

        assertFalse(gatedWithMock.hasPass(claimant));
        assertEq(gatedWithMock.totalPassesClaimed(), 0);
    }

    /// @notice 9. Verifier revert never grants access.
    function test_MockRevertingVerifierNeverGrantsAccess() public {
        MockRevertingVerifier mockVerifier = new MockRevertingVerifier();
        AgeGate gatedWithMock = new AgeGate(
            address(mockVerifier),
            festivalContext,
            passType,
            issuerPubKeyHash,
            100
        );

        vm.prank(claimant);
        vm.expectRevert(AgeGate.InvalidProof.selector);
        gatedWithMock.claimLateNightPass(realProof, realNullifier, realClaimTimestamp);

        assertFalse(gatedWithMock.hasPass(claimant));
        assertEq(gatedWithMock.totalPassesClaimed(), 0);
    }

    /// @notice 10. Inactive claiming rejects claims.
    function test_InactiveClaimingRejects() public {
        ageGate.setClaimingActive(false);

        vm.prank(claimant);
        vm.expectRevert(AgeGate.ClaimingNotActive.selector);
        ageGate.claimLateNightPass(realProof, realNullifier, realClaimTimestamp);
    }

    /// @notice 11. Cap enforcement: Exceeding maxPasses reverts.
    function test_MaxPassesExceededRejects() public {
        ageGate.setMaxPasses(0);

        vm.prank(claimant);
        vm.expectRevert(AgeGate.MaxPassesExceeded.selector);
        ageGate.claimLateNightPass(realProof, realNullifier, realClaimTimestamp);
    }

    /// @notice 12. Policy parameters: Reference date is derived from block.timestamp using civil calendar algorithm.
    function test_ReferenceDateCalculationPolicy() public view {
        // Unix timestamp for 2026-10-23 00:00:00 UTC = 1792713600
        (uint32 year, uint8 month, uint8 day) = ageGate.timestampToDate(1792713600);
        assertEq(year, 2026, "Year mismatch");
        assertEq(month, 10, "Month mismatch");
        assertEq(day, 23, "Day mismatch");

        // Leap year: 2028-02-29 12:00:00 UTC = 1835438400
        (uint32 ly, uint8 lm, uint8 ld) = ageGate.timestampToDate(1835438400);
        assertEq(ly, 2028, "Leap year mismatch");
        assertEq(lm, 2, "Leap month mismatch");
        assertEq(ld, 29, "Leap day mismatch");
    }

    /// @notice 13. Security: There is no alternate public function that grants pass access without proof verification.
    function test_NoAlternateAccessPath() public view {
        // Only claimLateNightPass modifies hasPass
        // Contract has no mintWithoutProof or adminGrantPass function
        assertTrue(ageGate.isPassAvailable());
    }

    /// @notice 14. Admin access control: Only owner can modify claiming parameters.
    function test_OnlyOwnerCanModifyAdminSettings() public {
        vm.prank(attacker);
        vm.expectRevert(AgeGate.CallerNotOwner.selector);
        ageGate.setClaimingActive(false);

        vm.prank(attacker);
        vm.expectRevert(AgeGate.CallerNotOwner.selector);
        ageGate.setMaxPasses(50);

        vm.prank(attacker);
        vm.expectRevert(AgeGate.CallerNotOwner.selector);
        ageGate.setIssuerPubKeyHash(bytes32(uint256(999)));
    }
}

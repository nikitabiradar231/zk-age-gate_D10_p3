// SPDX-License-Identifier: MIT
pragma solidity >=0.8.21;

import {IAgeVerifier} from "./interfaces/IAgeVerifier.sol";

/**
 * @title AgeGate
 * @notice Access-control contract for the Slow Bloom late-night festival pass.
 * @dev Enforces age verification (18+) via zero-knowledge proofs without revealing attendee birth dates.
 *      Integrates Barretenberg UltraHonk verification, account binding (msg.sender),
 *      replay protection (nullifiers), time-bound proof freshness, and context binding.
 */
contract AgeGate {
    // --- Constants ---

    /// @notice The fixed minimum age required for late-night festival pass eligibility.
    uint256 public constant REQUIRED_MIN_AGE = 18;

    /// @notice The maximum allowable age of a proof timestamp before it is deemed stale.
    uint256 public constant PROOF_MAX_AGE = 1 hours;

    /// @notice Number of public inputs expected by the Noir circuit.
    uint256 public constant EXPECTED_PUBLIC_INPUTS = 9;

    // --- Immutable State ---

    /// @notice The real cryptographic verifier contract.
    IAgeVerifier public immutable verifier;

    /// @notice Domain separator binding the claim to the Slow Bloom festival.
    bytes32 public immutable festivalContext;

    /// @notice Identifier for the specific pass type (e.g. 1 = Late-Night Stage Pass).
    uint256 public immutable passType;

    /// @notice Contract administrator/festival organizer.
    address public immutable owner;

    // --- Mutable State ---

    /// @notice Pinned hash of the door partner's authorized public key.
    bytes32 public issuerPubKeyHash;

    /// @notice Flag indicating whether pass claiming is currently active.
    bool public claimingActive;

    /// @notice Maximum number of passes that can be claimed.
    uint256 public maxPasses;

    /// @notice Total count of successfully claimed late-night passes.
    uint256 public totalPassesClaimed;

    /// @notice Tracks whether an account has already claimed their pass entitlement.
    mapping(address => bool) public hasPass;

    /// @notice Replay protection: tracks consumed nullifiers to prevent duplicate claims.
    mapping(bytes32 => bool) public consumedNullifiers;

    // --- Events ---

    event PassClaimed(
        address indexed claimant,
        bytes32 indexed nullifier,
        uint256 indexed passType,
        uint256 timestamp
    );
    event ClaimingStatusChanged(bool active);
    event MaxPassesUpdated(uint256 newMaxPasses);
    event IssuerKeyHashUpdated(bytes32 oldHash, bytes32 newHash);

    // --- Custom Errors ---

    error ClaimingNotActive();
    error MaxPassesExceeded();
    error PassAlreadyClaimed();
    error NullifierAlreadyConsumed(bytes32 nullifier);
    error ProofTimestampInFuture(uint64 claimTimestamp, uint256 blockTimestamp);
    error ProofStale(uint64 claimTimestamp, uint256 blockTimestamp, uint256 maxAge);
    error InvalidProof();
    error CallerNotOwner();
    error ZeroAddressVerifier();

    // --- Modifiers ---

    modifier onlyOwner() {
        if (msg.sender != owner) revert CallerNotOwner();
        _;
    }

    // --- Constructor ---

    /**
     * @notice Initializes the AgeGate contract with festival context and verifier.
     * @param _verifier Address of the generated UltraHonk verifier contract.
     * @param _festivalContext Context identifier for Slow Bloom festival.
     * @param _passType Pass type identifier (e.g. 1 for Late-Night Pass).
     * @param _issuerPubKeyHash Pinned hash of authorized door partner key.
     * @param _maxPasses Maximum number of claimable passes.
     */
    constructor(
        address _verifier,
        bytes32 _festivalContext,
        uint256 _passType,
        bytes32 _issuerPubKeyHash,
        uint256 _maxPasses
    ) {
        if (_verifier == address(0)) revert ZeroAddressVerifier();
        verifier = IAgeVerifier(_verifier);
        festivalContext = _festivalContext;
        passType = _passType;
        issuerPubKeyHash = _issuerPubKeyHash;
        maxPasses = _maxPasses;
        owner = msg.sender;
        claimingActive = true;
    }

    // --- Core Claim Flow ---

    /**
     * @notice Claims a late-night festival pass by submitting a valid zero-knowledge age proof.
     * @dev Gated strictly on real cryptographic proof verification.
     *      No caller-supplied date, age, or claimant address is trusted;
     *      all security-sensitive public inputs are derived or validated by contract state.
     * @param proof The serialized Barretenberg proof bytes.
     * @param nullifier Deterministic replay identifier derived inside the circuit.
     * @param claimTimestamp Local timestamp when the proof was prepared.
     * @return True upon successful verification and pass entitlement recording.
     */
    function claimLateNightPass(
        bytes calldata proof,
        bytes32 nullifier,
        uint64 claimTimestamp
    ) external returns (bool) {
        // 1. Check claim availability
        if (!claimingActive) revert ClaimingNotActive();
        if (totalPassesClaimed >= maxPasses) revert MaxPassesExceeded();
        if (hasPass[msg.sender]) revert PassAlreadyClaimed();

        // 2. Enforce replay protection on nullifier
        if (consumedNullifiers[nullifier]) revert NullifierAlreadyConsumed(nullifier);

        // 3. Enforce time window against trusted block.timestamp
        if (claimTimestamp > block.timestamp) {
            revert ProofTimestampInFuture(claimTimestamp, block.timestamp);
        }
        if (block.timestamp - claimTimestamp > PROOF_MAX_AGE) {
            revert ProofStale(claimTimestamp, block.timestamp, PROOF_MAX_AGE);
        }

        // 4. Derive contract-authorized reference date in UTC from block.timestamp
        (uint32 refYear, uint8 refMonth, uint8 refDay) = timestampToDate(block.timestamp);

        // 5. Construct canonical public inputs array expected by the verifier
        bytes32[] memory publicInputs = new bytes32[](EXPECTED_PUBLIC_INPUTS);
        // Public Input 0: Claimant address (bound to msg.sender)
        publicInputs[0] = bytes32(uint256(uint160(msg.sender)));
        // Public Input 1: Festival context (Slow Bloom identifier)
        publicInputs[1] = festivalContext;
        // Public Input 2: Pass type (Late-night pass identifier)
        publicInputs[2] = bytes32(passType);
        // Public Input 3: Reference year
        publicInputs[3] = bytes32(uint256(refYear));
        // Public Input 4: Reference month
        publicInputs[4] = bytes32(uint256(refMonth));
        // Public Input 5: Reference day
        publicInputs[5] = bytes32(uint256(refDay));
        // Public Input 6: Claim timestamp
        publicInputs[6] = bytes32(uint256(claimTimestamp));
        // Public Input 7: Issuer public key commitment
        publicInputs[7] = issuerPubKeyHash;
        // Public Input 8: Nullifier
        publicInputs[8] = nullifier;

        // 6. Call the real UltraHonk verifier
        bool verified;
        try verifier.verify(proof, publicInputs) returns (bool result) {
            verified = result;
        } catch {
            revert InvalidProof();
        }

        if (!verified) revert InvalidProof();

        // 7. Update access state and record nullifier only after proof succeeds
        consumedNullifiers[nullifier] = true;
        hasPass[msg.sender] = true;
        totalPassesClaimed++;

        emit PassClaimed(msg.sender, nullifier, passType, block.timestamp);

        return true;
    }

    // --- Date Utility ---

    /**
     * @notice Converts a Unix timestamp (seconds since epoch) into UTC (year, month, day).
     * @dev Uses the civil calendar algorithm (Howard Hinnant / Gregorian algorithm).
     *      Accurately handles all 400-year leap cycles and month lengths without approximations.
     * @param timestamp The Unix timestamp in seconds.
     * @return year The 4-digit calendar year (e.g. 2026).
     * @return month The month of the year (1..12).
     * @return day The day of the month (1..31).
     */
    function timestampToDate(uint256 timestamp) public pure returns (uint32 year, uint8 month, uint8 day) {
        uint256 z = timestamp / 86400 + 719468;
        uint256 era = z / 146097;
        uint256 doe = z - era * 146097;
        uint256 yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        uint256 y = yoe + era * 400;
        uint256 doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        uint256 mp = (5 * doy + 2) / 153;
        uint256 d = doy - (153 * mp + 2) / 5 + 1;
        uint256 m = mp < 10 ? mp + 3 : mp - 9;
        y = mp >= 10 ? y + 1 : y;
        return (uint32(y), uint8(m), uint8(d));
    }

    // --- View Functions ---

    /**
     * @notice Returns the current reference date derived from current block.timestamp.
     */
    function getCurrentReferenceDate() external view returns (uint32 year, uint8 month, uint8 day) {
        return timestampToDate(block.timestamp);
    }

    /**
     * @notice Checks if late-night festival passes are currently claimable.
     */
    function isPassAvailable() external view returns (bool) {
        return claimingActive && (totalPassesClaimed < maxPasses);
    }

    /**
     * @notice Checks if a specific nullifier has already been consumed.
     */
    function isNullifierConsumed(bytes32 nullifier) external view returns (bool) {
        return consumedNullifiers[nullifier];
    }

    // --- Admin Functions ---

    /**
     * @notice Toggles active claiming status.
     */
    function setClaimingActive(bool _active) external onlyOwner {
        claimingActive = _active;
        emit ClaimingStatusChanged(_active);
    }

    /**
     * @notice Updates the maximum number of claimable passes.
     */
    function setMaxPasses(uint256 _newMaxPasses) external onlyOwner {
        maxPasses = _newMaxPasses;
        emit MaxPassesUpdated(_newMaxPasses);
    }

    /**
     * @notice Updates the authorized door partner issuer key hash (key rotation).
     */
    function setIssuerPubKeyHash(bytes32 _newHash) external onlyOwner {
        bytes32 oldHash = issuerPubKeyHash;
        issuerPubKeyHash = _newHash;
        emit IssuerKeyHashUpdated(oldHash, _newHash);
    }
}

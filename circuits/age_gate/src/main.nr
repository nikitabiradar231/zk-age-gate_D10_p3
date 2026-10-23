use std::ecdsa_secp256k1::verify_signature;
use std::hash::keccak256;

fn is_leap_year(year: u32) -> bool {
    let mod4 = year % 4;
    let mod100 = year % 100;
    let mod400 = year % 400;
    ((mod4 == 0) & (mod100 != 0)) | (mod400 == 0)
}

fn days_in_month(year: u32, month: u8) -> u8 {
    if (month == 1) | (month == 3) | (month == 5) | (month == 7) | (month == 8) | (month == 10) | (month == 12) {
        31
    } else if (month == 4) | (month == 6) | (month == 9) | (month == 11) {
        30
    } else if month == 2 {
        if is_leap_year(year) {
            29
        } else {
            28
        }
    } else {
        0
    }
}

fn validate_date(year: u32, month: u8, day: u8) {
    assert(year >= 1900, "Year must be >= 1900");
    assert(year <= 2100, "Year must be <= 2100");
    assert((month >= 1) & (month <= 12), "Month must be between 1 and 12");
    let max_days = days_in_month(year, month);
    assert((day >= 1) & (day <= max_days), "Day out of range for month/year");
}

fn get_eighteenth_birthday(birth_year: u32, birth_month: u8, birth_day: u8) -> (u32, u8, u8) {
    let eighteenth_year = birth_year + 18;
    if (birth_month == 2) & (birth_day == 29) {
        // A leap-day baby legally completes their 18th year on March 1st in non-leap years
        (eighteenth_year, 3, 1)
    } else {
        (eighteenth_year, birth_month, birth_day)
    }
}

fn is_on_or_after(y1: u32, m1: u8, d1: u8, y2: u32, m2: u8, d2: u8) -> bool {
    if y1 > y2 {
        true
    } else if y1 < y2 {
        false
    } else {
        if m1 > m2 {
            true
        } else if m1 < m2 {
            false
        } else {
            d1 >= d2
        }
    }
}

fn is_on_or_before(y1: u32, m1: u8, d1: u8, y2: u32, m2: u8, d2: u8) -> bool {
    is_on_or_after(y2, m2, d2, y1, m1, d1)
}

fn pack_credential_payload(
    credential_id: [u8; 32],
    birth_year: u32,
    birth_month: u8,
    birth_day: u8,
    expiry_year: u32,
    expiry_month: u8,
    expiry_day: u8,
    buyer_id_commitment: [u8; 16],
) -> [u8; 56] {
    let mut payload: [u8; 56] = [0; 56];
    for i in 0..32 {
        payload[i] = credential_id[i];
    }
    payload[32] = ((birth_year >> 8) & 0xff) as u8;
    payload[33] = (birth_year & 0xff) as u8;
    payload[34] = birth_month;
    payload[35] = birth_day;
    payload[36] = ((expiry_year >> 8) & 0xff) as u8;
    payload[37] = (expiry_year & 0xff) as u8;
    payload[38] = expiry_month;
    payload[39] = expiry_day;
    for i in 0..16 {
        payload[40 + i] = buyer_id_commitment[i];
    }
    payload
}

fn compute_issuer_pubkey_hash(pub_key_x: [u8; 32], pub_key_y: [u8; 32]) -> Field {
    let mut key_bytes: [u8; 64] = [0; 64];
    for i in 0..32 {
        key_bytes[i] = pub_key_x[i];
        key_bytes[32 + i] = pub_key_y[i];
    }
    let h: [u8; 32] = keccak256(key_bytes, 64);
    // Convert first 31 bytes of hash to Field (fits in BN254 scalar field)
    let mut hash_field: Field = 0;
    for i in 0..31 {
        hash_field = hash_field * 256 + (h[i] as Field);
    }
    hash_field
}

fn compute_nullifier(
    credential_id: [u8; 32],
    buyer_secret: [u8; 32],
    festival_context: [u8; 32],
    pass_type: [u8; 32],
) -> Field {
    let mut preimage: [u8; 128] = [0; 128];
    for i in 0..32 {
        preimage[i] = credential_id[i];
        preimage[32 + i] = buyer_secret[i];
        preimage[64 + i] = festival_context[i];
        preimage[96 + i] = pass_type[i];
    }
    let h: [u8; 32] = keccak256(preimage, 128);
    let mut nullifier_field: Field = 0;
    for i in 0..31 {
        nullifier_field = nullifier_field * 256 + (h[i] as Field);
    }
    nullifier_field
}

fn main(
    // Public Inputs (enforced and checked by the smart contract)
    claimant: pub Field,
    festival_context: pub Field,
    pass_type: pub Field,
    ref_year: pub u32,
    ref_month: pub u8,
    ref_day: pub u8,
    claim_timestamp: pub u64,
    issuer_pubkey_hash: pub Field,
    nullifier: pub Field,

    // Private Witness Inputs (held solely on the buyer device, never disclosed)
    birth_year: u32,
    birth_month: u8,
    birth_day: u8,
    expiry_year: u32,
    expiry_month: u8,
    expiry_day: u8,
    credential_id: [u8; 32],
    buyer_secret: [u8; 32],
    issuer_pub_x: [u8; 32],
    issuer_pub_y: [u8; 32],
    issuer_signature: [u8; 64],
) {
    // 1. Validate dates are well-formed calendar dates
    validate_date(ref_year, ref_month, ref_day);
    validate_date(birth_year, birth_month, birth_day);
    validate_date(expiry_year, expiry_month, expiry_day);

    // 2. Validate reference date is on or before credential expiry date
    assert(
        is_on_or_before(ref_year, ref_month, ref_day, expiry_year, expiry_month, expiry_day),
        "Credential has expired on the reference date",
    );

    // 3. Cryptographically enforce the 18+ requirement
    let (eighteenth_year, eighteenth_month, eighteenth_day) =
        get_eighteenth_birthday(birth_year, birth_month, birth_day);
    assert(
        is_on_or_after(ref_year, ref_month, ref_day, eighteenth_year, eighteenth_month, eighteenth_day),
        "Buyer has not reached 18th birthday on the authorized reference date",
    );

    // 4. Verify authorized issuer key matches the contract-pinned public key hash
    let computed_issuer_hash = compute_issuer_pubkey_hash(issuer_pub_x, issuer_pub_y);
    assert(
        computed_issuer_hash == issuer_pubkey_hash,
        "Issuer public key does not match contract authorized issuer hash",
    );

    // 5. Extract buyer ID commitment from buyer secret
    let mut buyer_id_commitment: [u8; 16] = [0; 16];
    for i in 0..16 {
        buyer_id_commitment[i] = buyer_secret[16 + i];
    }

    // 6. Reconstruct credential payload and authenticate door partner signature
    let payload = pack_credential_payload(
        credential_id,
        birth_year,
        birth_month,
        birth_day,
        expiry_year,
        expiry_month,
        expiry_day,
        buyer_id_commitment,
    );
    let credential_hash: [u8; 32] = keccak256(payload, 56);

    let is_sig_valid = verify_signature(
        issuer_pub_x,
        issuer_pub_y,
        issuer_signature,
        credential_hash,
    );
    assert(is_sig_valid, "Door partner credential signature verification failed");

    // 7. Derive deterministic, domain-separated nullifier
    let context_bytes: [u8; 32] = festival_context.to_be_bytes();
    let pass_type_bytes: [u8; 32] = pass_type.to_be_bytes();
    let expected_nullifier = compute_nullifier(
        credential_id,
        buyer_secret,
        context_bytes,
        pass_type_bytes,
    );
    assert(nullifier == expected_nullifier, "Nullifier derivation mismatch");

    // 8. Bind claimant account and claim timestamp into circuit constraints
    assert(claimant != 0, "Claimant address cannot be zero");
    assert(claim_timestamp != 0, "Claim timestamp cannot be zero");
}

#[test]
fn test_age_boundaries_18th_birthday() {
    let (ey, em, ed) = get_eighteenth_birthday(2008, 10, 24);
    assert(ey == 2026);
    assert(em == 10);
    assert(ed == 24);
    assert(is_on_or_after(2026, 10, 24, ey, em, ed));
}

#[test]
fn test_age_boundaries_day_before_18th_birthday() {
    let (ey, em, ed) = get_eighteenth_birthday(2008, 10, 24);
    assert(!is_on_or_after(2026, 10, 23, ey, em, ed));
}

#[test]
fn test_leap_day_birthday_boundaries() {
    let (ey, em, ed) = get_eighteenth_birthday(2008, 2, 29);
    assert(ey == 2026);
    assert(em == 3);
    assert(ed == 1);

    // On 2026-02-28: not yet 18
    assert(!is_on_or_after(2026, 2, 28, ey, em, ed));

    // On 2026-03-01: reached 18th birthday
    assert(is_on_or_after(2026, 3, 1, ey, em, ed));
}

#[test]
fn test_leap_year_rules() {
    assert(is_leap_year(2000));
    assert(!is_leap_year(1900));
    assert(is_leap_year(2008));
    assert(!is_leap_year(2026));
}

#[test]
fn test_date_validations() {
    validate_date(2026, 10, 23);
    validate_date(2008, 2, 29);
    validate_date(2026, 2, 28);
}

#[test(should_fail)]
fn test_invalid_leap_day_fails() {
    validate_date(2025, 2, 29);
}

#[test(should_fail)]
fn test_invalid_month_fails() {
    validate_date(2026, 13, 1);
}

#[test(should_fail)]
fn test_invalid_day_fails() {
    validate_date(2026, 4, 31);
}

#[test(should_fail)]
fn test_underage_candidate_fails() {
    let (ey, em, ed) = get_eighteenth_birthday(2010, 5, 15);
    // Reference date 2026-10-23: age is 16, must fail assertion
    assert(is_on_or_after(2026, 10, 23, ey, em, ed));
}

#[test(should_fail)]
fn test_expired_credential_fails() {
    // Reference date 2026-10-23, expiry 2025-12-31: must fail assertion
    assert(is_on_or_before(2026, 10, 23, 2025, 12, 31));
}

#[test(should_fail)]
fn test_year_too_early_fails() {
    validate_date(1899, 1, 1);
}

#[test(should_fail)]
fn test_year_too_late_fails() {
    validate_date(2101, 1, 1);
}

#[test]
fn test_credential_payload_packing() {
    let cred_id: [u8; 32] = [1; 32];
    let buyer_id: [u8; 16] = [2; 16];
    let payload = pack_credential_payload(cred_id, 2005, 7, 12, 2030, 12, 31, buyer_id);
    assert(payload[0] == 1);
    assert(payload[31] == 1);
    assert(payload[32] == ((2005 >> 8) & 0xff) as u8);
    assert(payload[33] == (2005 & 0xff) as u8);
    assert(payload[34] == 7);
    assert(payload[35] == 12);
    assert(payload[40] == 2);
}


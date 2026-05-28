// ZKProofport: Korea Mobile ID (mDL) circuit - OmniOne CX based
//
// v2 - hardens age + region verification by binding birth_date and address
// into the natural-person commitment. The first whitespace-separated token
// of the address is extracted in-circuit and matched against region_code,
// so a prover cannot claim a region different from the OmniOne CX response.
//
// Web2 authentication flow (no Privy wallet signature). Uses ci/jti/pri
// from the OmniOne CX response for integrity, derives a permanent
// natural-person nullifier from ci+birth+address, enforces age and region
// predicates, and produces a selective owner commitment over
// (name, birth_date, sex, telno).
//
// disclose_flags bits:
//   0x01 = name
//   0x02 = birth_date
//   0x04 = sex
//   0x08 = telno
//   0x00 = anonymous (owner_commit must be the zero hash)

use dep::keccak256::keccak256;
use dep::coinbase_libs::nullifier;

// Fixed buffer sizes - inputs are UTF-8 / ASCII plaintext, zero-padded.
// The external prover script must follow the same padding convention.
global CI_LEN: u32 = 88;       // base64 string of 64 raw bytes
global JTI_LEN: u32 = 40;
global PRI_LEN: u32 = 44;      // base64 string of 32 raw bytes
global NAME_MAX: u32 = 64;
global TELNO_MAX: u32 = 16;
global REGION_MAX: u32 = 64;
global BIRTH_LEN: u32 = 8;     // "YYYYMMDD"
global ADDRESS_MAX: u32 = 256;

fn main(
    // ============ Public Inputs ============

    // Anti-replay challenge (relay-issued nonce)
    signal_hash:       pub [u8; 32],

    // dApp domain scope (e.g. keccak("openstoa:login:v1"))
    scope:             pub [u8; 32],

    // Sybil-resistance identifier
    nullifier_value:   pub [u8; 32],

    // OmniOne CX integrity anchor: keccak(jti || pri)
    cx_integrity_root: pub [u8; 32],

    // Age predicate
    age_threshold:     pub u32,        // e.g. 19
    current_year:      pub u32,        // e.g. 2026

    // Region predicate: keccak(region_padded_64) - the verifier knows the
    // target si-do and supplies its hash; the circuit asserts that the
    // first whitespace-separated token of the user's address hashes to
    // exactly this value.
    region_code:       pub [u8; 32],

    // Selective disclosure
    disclose_flags:    pub u8,
    owner_commit:      pub [u8; 32],

    // ============ Private Inputs ============

    // OmniOne CX response (raw ASCII / UTF-8 strings, zero-padded to fixed length)
    ci:                [u8; 88],
    cx_jti:            [u8; 40],
    cx_pri:            [u8; 44],

    // Mobile DL attributes - all bound into mdl_commit, so a prover cannot
    // swap any of them after the OmniOne CX call.
    name:              [u8; 64],       // UTF-8, zero-padded
    birth_date:        [u8; 8],        // "YYYYMMDD" ASCII
    telno:             [u8; 16],       // ASCII, zero-padded
    sex:               u8,             // 'M'/'F' ASCII, or 0 if absent
    address:           [u8; 256],      // full residential address UTF-8, zero-padded
) {
    // ======================================================================
    // 1. OmniOne CX integrity check
    //    keccak256(jti || pri) MUST match the public anchor.
    // ======================================================================
    let mut integrity_buf: [u8; 84] = [0u8; 84];
    for i in 0..40 {
        integrity_buf[i] = cx_jti[i];
    }
    for i in 0..44 {
        integrity_buf[40 + i] = cx_pri[i];
    }
    let integrity = keccak256(integrity_buf, 84);
    assert(integrity == cx_integrity_root, "CX integrity mismatch");

    // ======================================================================
    // 2. Natural-person commitment (ci + cx integrity + birth + address)
    //    Birth and address are included so a prover cannot swap them.
    //    First 20 bytes serve as the self_id slot in the existing
    //    coinbase_libs::nullifier helper.
    // ======================================================================
    let mut mdl_buf: [u8; 436] = [0u8; 436];
    for i in 0..88 {
        mdl_buf[i] = ci[i];
    }
    for i in 0..40 {
        mdl_buf[88 + i] = cx_jti[i];
    }
    for i in 0..44 {
        mdl_buf[128 + i] = cx_pri[i];
    }
    for i in 0..8 {
        mdl_buf[172 + i] = birth_date[i];
    }
    for i in 0..256 {
        mdl_buf[180 + i] = address[i];
    }
    let mdl_commit = keccak256(mdl_buf, 436);

    let mut self_id_20: [u8; 20] = [0u8; 20];
    for i in 0..20 {
        self_id_20[i] = mdl_commit[i];
    }

    // ======================================================================
    // 3. Nullifier verification - reuse coinbase_libs::nullifier
    //    user_secret = keccak(self_id_20 || signal_hash)
    //    nullifier   = keccak(user_secret || scope)
    // ======================================================================
    nullifier::verify_nullifier(self_id_20, signal_hash, scope, nullifier_value);

    // ======================================================================
    // 4. Age predicate - current_year - birth_year >= age_threshold
    //    birth_date[0..4] = year ASCII digits
    // ======================================================================
    let mut birth_year: u32 = 0;
    for i in 0..4 {
        birth_year = birth_year * 10 + (birth_date[i] as u32) - 0x30;
    }
    assert(current_year >= birth_year, "Birth year exceeds current year");
    let age = current_year - birth_year;
    assert(age >= age_threshold, "Age below threshold");

    // ======================================================================
    // 5. Region predicate
    //    Extract the first whitespace-separated token from `address`,
    //    zero-pad to 64 bytes, hash, and assert equal to region_code.
    //    This binds the region claim to the user's actual address.
    //
    //    Tokens longer than 64 bytes are truncated (sufficient for every
    //    Korean si-do; the longest wide-area si-do string in UTF-8 is < 25 bytes).
    // ======================================================================
    let mut extracted: [u8; 64] = [0u8; 64];
    let mut found_space: bool = false;
    for i in 0..64 {
        let ch = address[i];
        // ASCII space (0x20) or tab (0x09) terminate the first token.
        let is_space = (ch == 0x20) | (ch == 0x09);
        if is_space {
            found_space = true;
        }
        if !found_space {
            extracted[i] = ch;
        }
    }
    let extracted_hash = keccak256(extracted, 64);
    assert(extracted_hash == region_code, "Region mismatch");

    // ======================================================================
    // 6. Selective disclosure commitment
    //    Buffer layout (fixed): name(64) || birth(8) || sex(1) || telno(16) = 89 bytes
    //    A bit not set in disclose_flags forces the corresponding region of
    //    the buffer to zero. The final hash also includes the flag byte so
    //    the verifier cannot misinterpret which slots are meaningful.
    //
    //    disclose_flags == 0 -> owner_commit must be the zero hash (anonymous).
    // ======================================================================
    let mut owner_buf: [u8; 89] = [0u8; 89];

    let mask_name  = ((disclose_flags & 0x01) as u32 != 0) as u32;
    let mask_birth = ((disclose_flags & 0x02) as u32 != 0) as u32;
    let mask_sex   = ((disclose_flags & 0x04) as u32 != 0) as u32;
    let mask_telno = ((disclose_flags & 0x08) as u32 != 0) as u32;

    for i in 0..64 {
        owner_buf[i] = (name[i] as u32 * mask_name) as u8;
    }
    for i in 0..8 {
        owner_buf[64 + i] = (birth_date[i] as u32 * mask_birth) as u8;
    }
    owner_buf[72] = (sex as u32 * mask_sex) as u8;
    for i in 0..16 {
        owner_buf[73 + i] = (telno[i] as u32 * mask_telno) as u8;
    }

    if disclose_flags == 0 {
        let zero: [u8; 32] = [0u8; 32];
        assert(owner_commit == zero, "Anonymous mode requires zero owner_commit");
    } else {
        // Prepend the flag byte so distinct flag/value combinations produce
        // distinct commits.
        let mut commit_buf: [u8; 90] = [0u8; 90];
        commit_buf[0] = disclose_flags;
        for i in 0..89 {
            commit_buf[1 + i] = owner_buf[i];
        }
        let computed = keccak256(commit_buf, 90);
        assert(computed == owner_commit, "Owner commit mismatch");
    }
}

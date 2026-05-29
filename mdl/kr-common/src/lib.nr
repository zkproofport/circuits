// ZKProofport: Korea Mobile ID (mDL) common helpers. v4.
//
// Shared by mdl_kr_ownership, mdl_kr_age, and mdl_kr_region.
//
// v4 change: nullifier formula simplified to OIDC-style keccak(keccak(ci) || scope).
// The previous formula used a coinbase_libs helper that required signal_hash
// (anti-replay) and a self_id_20 derived from ci || jti || pri || birth || address.
// Both of those require HS256 session anchoring (cx_integrity_root, cx_jti, cx_pri)
// which we cannot verify until RAON registration provides the RP shared secret.
// The new formula is simpler and does not depend on HS256 at all.

use dep::keccak256::keccak256;

// Fixed buffer sizes - inputs are UTF-8 / ASCII plaintext, zero-padded.
// All circuits and external provers (mobile mopro, gen_prover_toml.mjs)
// MUST follow these sizes exactly.
global CI_LEN: u32      = 88;
// TODO(HS256): Re-enable when RAON registration provides the RP shared
// secret. Currently disabled because no off-chain HS256 verifier exists,
// so cx_integrity_root cannot anchor anything meaningfully.
// global JTI_LEN: u32     = 40;
// global PRI_LEN: u32     = 44;
global NAME_MAX: u32    = 64;
global TELNO_MAX: u32   = 16;
global REGION_MAX: u32  = 64;
global BIRTH_LEN: u32   = 8;
global ADDRESS_MAX: u32 = 256;

// TODO(HS256): Re-enable when RAON registration provides the RP shared
// secret. Currently disabled because no off-chain HS256 verifier exists,
// so cx_integrity_root cannot anchor anything meaningfully.
//
// keccak256(jti || pri) == public cx_integrity_root.
// OmniOne CX returns jti+pri inside an HS256-signed envelope; this anchor
// links the proof to a specific CX session without exposing jti/pri.
//
// pub fn verify_cx_integrity(
//     jti: [u8; 40],
//     pri: [u8; 44],
//     cx_integrity_root: [u8; 32],
// ) {
//     let mut buf: [u8; 84] = [0u8; 84];
//     for i in 0..40 {
//         buf[i] = jti[i];
//     }
//     for i in 0..44 {
//         buf[40 + i] = pri[i];
//     }
//     let computed = keccak256(buf, 84);
//     assert(computed == cx_integrity_root, "CX integrity mismatch");
// }

// TODO(HS256): Re-enable when RAON registration provides the RP shared
// secret. Currently disabled because no off-chain HS256 verifier exists,
// so cx_integrity_root cannot anchor anything meaningfully.
//
// mdl_commit = keccak(ci || jti || pri || birth || address) - 436 bytes -
// then take the first 20 bytes as the self_id slot for the coinbase_libs
// nullifier helper. Birth and address are included so a prover cannot
// swap them after the OmniOne CX call.
//
// pub fn derive_self_id_20(
//     ci:      [u8; 88],
//     jti:     [u8; 40],
//     pri:     [u8; 44],
//     birth:   [u8; 8],
//     address: [u8; 256],
// ) -> [u8; 20] {
//     let mut buf: [u8; 436] = [0u8; 436];
//     for i in 0..88 {
//         buf[i] = ci[i];
//     }
//     for i in 0..40 {
//         buf[88 + i] = jti[i];
//     }
//     for i in 0..44 {
//         buf[128 + i] = pri[i];
//     }
//     for i in 0..8 {
//         buf[172 + i] = birth[i];
//     }
//     for i in 0..256 {
//         buf[180 + i] = address[i];
//     }
//     let commit = keccak256(buf, 436);
//     let mut id: [u8; 20] = [0u8; 20];
//     for i in 0..20 {
//         id[i] = commit[i];
//     }
//     id
// }

// Nullifier derivation (v4 - OIDC-style, no HS256 dependency).
//
// nullifier = keccak( keccak(ci) || scope )
//
// This mirrors the oidc-domain-attestation formula exactly
// (replacing `email` with `ci`). Properties:
//   - Same user (ci) + same scope  -> same nullifier (sybil resistance)
//   - Same user (ci) + diff scope  -> different nullifier
//   - Different user (ci) + same scope -> different nullifier
//
// `ci` is the Connecting Information issued by RAON --
// a pseudonymous identifier stable across provider types for the same
// natural person.
pub fn verify_nullifier(ci: [u8; 88], scope: [u8; 32], nullifier: [u8; 32]) {
    let ci_hash: [u8; 32] = keccak256(ci, 88);

    let mut preimage: [u8; 64] = [0; 64];
    for i in 0..32 {
        preimage[i] = ci_hash[i];
    }
    for i in 0..32 {
        preimage[32 + i] = scope[i];
    }
    let expected: [u8; 32] = keccak256(preimage, 64);
    assert(nullifier == expected, "nullifier mismatch");
}

// Age predicate: current_year - birth_year >= age_threshold.
// birth_date[0..4] is the ASCII year. The first check rejects underflow
// when current_year < birth_year (e.g., a tampered current_year).
pub fn assert_age(birth: [u8; 8], current_year: u32, age_threshold: u32) {
    let mut birth_year: u32 = 0;
    for i in 0..4 {
        birth_year = birth_year * 10 + (birth[i] as u32) - 0x30;
    }
    assert(current_year >= birth_year, "Birth year exceeds current year");
    let age = current_year - birth_year;
    assert(age >= age_threshold, "Age below threshold");
}

// Extract the first whitespace-separated token from `address` as a zero-
// padded 64-byte buffer.
//   1. Skip leading whitespace / zero padding.
//   2. Copy bytes into `extracted` until the next whitespace OR zero byte.
//   3. Tokens longer than 64 bytes are silently truncated (the longest
//      Korean wide-area si/do in UTF-8 is < 25 bytes).
pub fn extract_region_token(address: [u8; 256]) -> [u8; 64] {
    let mut extracted: [u8; 64] = [0u8; 64];
    let mut started: bool = false;
    let mut ended: bool = false;
    let mut out_idx: u32 = 0;
    for i in 0..256 {
        let ch = address[i];
        let is_space = (ch == 0x20) | (ch == 0x09);
        let is_zero = ch == 0;
        if !ended {
            if !started {
                if !is_space & !is_zero {
                    started = true;
                    if out_idx < 64 {
                        extracted[out_idx] = ch;
                        out_idx = out_idx + 1;
                    }
                }
            } else {
                if is_space | is_zero {
                    ended = true;
                } else if out_idx < 64 {
                    extracted[out_idx] = ch;
                    out_idx = out_idx + 1;
                }
            }
        }
    }
    extracted
}

// Selective disclosure commitment.
//
// The user or dApp pre-computes
//   owner_commit = keccak(flag || masked(name) || masked(telno) ||
//                         masked(birth) || masked(sex))
// off-circuit and supplies it as a PUBLIC input. The circuit recomputes
// the same hash from the mDL values (private, bound into mdl_commit)
// and asserts equality. Expected plaintext values are NEVER fed into
// the circuit, so the proof and witness never contain user PII.
//
//   Buffer layout (89 bytes): name(64) || telno(16) || birth(8) || sex(1).
//   A bit not set in disclose_flags forces the corresponding slot to
//   zero. The flag byte is prepended to the hash input so distinct
//   (flag, value) combinations produce distinct commits.
//
//   disclose_flags == 0 -> owner_commit MUST be the 32-byte zero hash
//   (anonymous mode). Otherwise the recomputed hash must match.
pub fn assert_owner_commit(
    disclose_flags: u8,
    // mDL values (private, bound into mdl_commit)
    name:           [u8; 64],
    birth:          [u8; 8],
    sex:            u8,
    telno:          [u8; 16],
    owner_commit:   [u8; 32],
) {
    let mask_name  = ((disclose_flags & 0x01) as u32 != 0) as u32;
    let mask_birth = ((disclose_flags & 0x02) as u32 != 0) as u32;
    let mask_sex   = ((disclose_flags & 0x04) as u32 != 0) as u32;
    let mask_telno = ((disclose_flags & 0x08) as u32 != 0) as u32;

    // owner_commit = keccak(flag || masked(name) || masked(telno) ||
    //                       masked(birth) || masked(sex))
    // Order is name -> telno -> birth -> sex (89 bytes total).
    let mut owner_buf: [u8; 89] = [0u8; 89];
    for i in 0..64 {
        owner_buf[i] = (name[i] as u32 * mask_name) as u8;
    }
    for i in 0..16 {
        owner_buf[64 + i] = (telno[i] as u32 * mask_telno) as u8;
    }
    for i in 0..8 {
        owner_buf[80 + i] = (birth[i] as u32 * mask_birth) as u8;
    }
    owner_buf[88] = (sex as u32 * mask_sex) as u8;

    if disclose_flags == 0 {
        let zero: [u8; 32] = [0u8; 32];
        assert(owner_commit == zero, "Anonymous mode requires zero owner_commit");
    } else {
        let mut commit_buf: [u8; 90] = [0u8; 90];
        commit_buf[0] = disclose_flags;
        for i in 0..89 {
            commit_buf[1 + i] = owner_buf[i];
        }
        let computed = keccak256(commit_buf, 90);
        assert(computed == owner_commit, "Owner commit mismatch");
    }
}

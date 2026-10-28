// Android key attestation, verified in a circuit: "a P-256 key generated in
// secure hardware by THIS app (as Google Play signs it) on a device with a
// locked bootloader and verified boot". The caller then checks that key's
// signature over its statement.
//
// THE CHAIN, and why only this one (decided 2026-10-28,
// .claude/agents/circuits-dev.md "Android signer"). Every chain Google's
// Remote Key Provisioning (RKP) issues today has this shape, read from real
// devices (android/keyattestation testdata, Android 16/17, 2026):
//
//   Key Attestation CA1   P-384 root, pinned by the caller (Google publishes
//                         it; it signs attestation chains from 2026-02-01;
//                         valid to 2035-07-15)
//     -> Droid CA2        P-384, ecdsa-with-SHA384 by the root, ~3 years
//     -> Droid CA3        P-256, ecdsa-with-SHA384 by CA2, ~10 weeks
//     -> attestation key  P-256, ecdsa-with-SHA256 by CA3, ~2 weeks; carries
//                         the provisioning-information extension (RKP's mark)
//     -> leaf             P-256, ecdsa-with-SHA256 by the attestation key;
//                         carries the key attestation extension
//
// Factory-provisioned chains (the RSA root, OEM intermediates) are refused:
// Google's revocation policy says leaked attestation keys -- the ones on the
// published revocation list -- are factory keys, and "don't apply to
// attestation keys certified by ... RKP". A circuit cannot read that list, so
// it accepts only the provisioning that does not need it. RKP's own answer to
// a compromised device is short certificates; hence CA2, CA3 and the
// attestation-key certificate must all be valid at `now`, as Google requires
// for RKP ("continue to have their validity period checked"). zkPassport
// accepts both roots and every intermediate count, one circuit per shape, and
// leans on a Play Integrity token for the rest; see key_description.nr.
//
// FIXED POSITIONS. The key attestation extension is trusted only in the leaf,
// directly below the certificate with the provisioning-information extension
// (Google: "Only the first occurrence of the extension in the chain can be
// trusted"). The shape above fixes those positions; nothing is searched for.

pub mod time;
pub mod cert;
pub mod key_description;
mod tests;
mod test_vectors;

use app_attest::intermediate::verify_intermediate_signature;
use cert::{
    assert_ca, assert_valid_at, find_extension, OID_KEY_ATTESTATION, OID_PROVISIONING_INFO,
    p256_key, p384_key, SIG_ALG_ECDSA_SHA256, SIG_ALG_ECDSA_SHA384, walk_tbs,
};
use key_description::check_key_description;

/// TBS room per certificate. Real lengths (2026): CA2 495, CA3 633,
/// attestation key 393-400, leaf 611-709. SHA-384 pads to 128-byte blocks
/// and SHA-256 to 64; each limit leaves room for longer names or more
/// authorizations without another block of hashing than necessary.
pub global CA2_TBS_MAX_LEN: u32 = 600;
pub global CA3_TBS_MAX_LEN: u32 = 768;
pub global ATT_TBS_MAX_LEN: u32 = 512;
pub global LEAF_TBS_MAX_LEN: u32 = 1024;

/// Everything below the pinned root a device contributes. Signatures are
/// r || s with s in low form (the prover replaces s with n - s when needed:
/// the same signature; both curves' checks refuse the high form).
pub struct AndroidChain {
    pub ca2_tbs: [u8; CA2_TBS_MAX_LEN],
    pub ca2_tbs_len: u32,
    pub ca2_sig: [u8; 96],
    pub ca3_tbs: [u8; CA3_TBS_MAX_LEN],
    pub ca3_tbs_len: u32,
    pub ca3_sig: [u8; 96],
    pub att_tbs: [u8; ATT_TBS_MAX_LEN],
    pub att_tbs_len: u32,
    pub att_sig: [u8; 64],
    pub leaf_tbs: [u8; LEAF_TBS_MAX_LEN],
    pub leaf_tbs_len: u32,
    pub leaf_sig: [u8; 64],
}

fn split48(sig: [u8; 96]) -> ([u8; 48], [u8; 48]) {
    let mut r: [u8; 48] = [0; 48];
    let mut s: [u8; 48] = [0; 48];
    for i in 0..48 {
        r[i] = sig[i];
        s[i] = sig[48 + i];
    }
    (r, s)
}

/// The leaf's P-256 key, X and Y. Asserts every link from the pinned root
/// down, each certificate's shape, the validity of CA2, CA3 and the
/// attestation-key certificate at `now`, and the leaf's key description
/// (key_description.nr) for `package` signed with `signing_digest`.
pub fn android_signing_key<let P: u32>(
    chain: AndroidChain,
    root_x: [u8; 48],
    root_y: [u8; 48],
    package: [u8; P],
    signing_digest: [u8; 32],
    now: u64,
) -> ([u8; 32], [u8; 32]) {
    assert(chain.leaf_tbs_len != 0, "No Android key attestation chain");
    // Named here, before any hash reads a length past its array (the hash
    // libraries refuse that without a message).
    assert(
        (chain.ca2_tbs_len <= CA2_TBS_MAX_LEN)
            & (chain.ca3_tbs_len <= CA3_TBS_MAX_LEN)
            & (chain.att_tbs_len <= ATT_TBS_MAX_LEN)
            & (chain.leaf_tbs_len <= LEAF_TBS_MAX_LEN),
        "Certificate TBS longer than the circuit allows",
    );

    // root -> CA2
    let (r2, s2) = split48(chain.ca2_sig);
    assert(
        verify_intermediate_signature(root_x, root_y, chain.ca2_tbs, chain.ca2_tbs_len, r2, s2),
        "Droid CA2 is not signed by the pinned Google root",
    );
    let ca2 = walk_tbs(chain.ca2_tbs, chain.ca2_tbs_len, SIG_ALG_ECDSA_SHA384, true);
    assert_ca(chain.ca2_tbs, ca2);
    assert_valid_at(ca2, now);
    let (ca2_x, ca2_y) = p384_key(chain.ca2_tbs, ca2);

    // CA2 -> CA3
    let (r3, s3) = split48(chain.ca3_sig);
    assert(
        verify_intermediate_signature(ca2_x, ca2_y, chain.ca3_tbs, chain.ca3_tbs_len, r3, s3),
        "Droid CA3 is not signed by Droid CA2",
    );
    let ca3 = walk_tbs(chain.ca3_tbs, chain.ca3_tbs_len, SIG_ALG_ECDSA_SHA384, true);
    assert_ca(chain.ca3_tbs, ca3);
    assert_valid_at(ca3, now);
    let (ca3_x, ca3_y) = p256_key(chain.ca3_tbs, ca3);

    // CA3 -> RKP attestation key
    let att_digest = sha256::sha256_var(chain.att_tbs, chain.att_tbs_len);
    assert(
        std::ecdsa_secp256r1::verify_signature(ca3_x, ca3_y, chain.att_sig, att_digest),
        "Attestation key certificate is not signed by Droid CA3",
    );
    let att = walk_tbs(chain.att_tbs, chain.att_tbs_len, SIG_ALG_ECDSA_SHA256, true);
    assert_ca(chain.att_tbs, att);
    assert_valid_at(att, now);
    let (pi_count, _, _) = find_extension(chain.att_tbs, att, OID_PROVISIONING_INFO);
    assert(pi_count == 1, "Attestation key was not remotely provisioned");
    let (ka_in_att, _, _) = find_extension(chain.att_tbs, att, OID_KEY_ATTESTATION);
    assert(ka_in_att == 0, "Attestation key certificate carries a key description");
    let (att_x, att_y) = p256_key(chain.att_tbs, att);

    // attestation key -> leaf
    let leaf_digest = sha256::sha256_var(chain.leaf_tbs, chain.leaf_tbs_len);
    assert(
        std::ecdsa_secp256r1::verify_signature(att_x, att_y, chain.leaf_sig, leaf_digest),
        "Leaf certificate is not signed by the attestation key",
    );
    // The leaf's validity is the app's own choice (KeyGenParameterSpec), so it
    // is not read.
    let leaf = walk_tbs(
        chain.leaf_tbs,
        chain.leaf_tbs_len,
        SIG_ALG_ECDSA_SHA256,
        false,
    );
    let (ka_count, ka_at, ka_len) = find_extension(chain.leaf_tbs, leaf, OID_KEY_ATTESTATION);
    assert(ka_count == 1, "Leaf certificate has no single key description");
    let _ = check_key_description(chain.leaf_tbs, ka_at, ka_len, package, signing_digest);

    p256_key(chain.leaf_tbs, leaf)
}

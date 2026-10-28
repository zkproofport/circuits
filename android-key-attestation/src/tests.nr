// Tests on REAL Google-signed chains (test_vectors.nr). Accepting the chain
// end to end needs Google's test app as the package; with ours it must be
// refused. Refusals that need a re-signed certificate (a leaf with another
// boot state, say) are covered twice: here by calling the key-description
// check directly on the real leaf with one byte changed (no signature
// involved), and in each circuit's acceptance run with synthetic chains
// signed by keys the fixtures hold.

use crate::{android_factory_signing_key, android_signing_key, AndroidChain, FactoryChain};
use crate::cert::{p384_key, SIG_ALG_ECDSA_SHA384, walk_tbs};
use crate::key_description::check_key_description;
use crate::test_vectors::{
    BLUELINE_BATCH_SIG, BLUELINE_BATCH_TBS, BLUELINE_BATCH_TBS_LEN, BLUELINE_DIGEST,
    BLUELINE_IK_SIG, BLUELINE_IK_TBS, BLUELINE_IK_TBS_LEN, BLUELINE_LEAF_KEY, BLUELINE_LEAF_SIG,
    BLUELINE_LEAF_TBS, BLUELINE_LEAF_TBS_LEN, BLUELINE_PACKAGE, RSA_ROOT_MODULUS, RSA_ROOT_REDC,
    SB_ATT_LEVEL, SB_ATT_SIG, SB_ATT_TBS, SB_ATT_TBS_LEN, SB_BOOT_STATE, SB_CA2_SIG, SB_CA2_TBS,
    SB_CA2_TBS_LEN, SB_CA3_SIG, SB_CA3_TBS, SB_CA3_TBS_LEN, SB_DIGEST, SB_DIGEST_AT, SB_KA_AT,
    SB_KA_LEN, SB_KM_LEVEL, SB_LEAF_KEY, SB_LEAF_SIG, SB_LEAF_TBS, SB_LEAF_TBS_LEN, SB_LOCKED,
    SB_ORIGIN, SB_PACKAGE, SB_PKG_AT, SONY_BATCH_SIG, SONY_BATCH_TBS, SONY_BATCH_TBS_LEN,
    SONY_DIGEST, SONY_IK_SIG, SONY_IK_TBS, SONY_IK_TBS_LEN, SONY_LEAF_KEY, SONY_LEAF_SIG,
    SONY_LEAF_TBS, SONY_LEAF_TBS_LEN, SONY_PACKAGE, TEE_ATT_LEVEL, TEE_ATT_SIG, TEE_ATT_TBS,
    TEE_ATT_TBS_LEN, TEE_BOOT_STATE, TEE_CA2_SIG, TEE_CA2_TBS, TEE_CA2_TBS_LEN, TEE_CA3_SIG,
    TEE_CA3_TBS, TEE_CA3_TBS_LEN, TEE_DIGEST, TEE_DIGEST_AT, TEE_KA_AT, TEE_KA_LEN, TEE_KM_LEVEL,
    TEE_LEAF_KEY, TEE_LEAF_SIG, TEE_LEAF_TBS, TEE_LEAF_TBS_LEN, TEE_LOCKED, TEE_ORIGIN, TEE_PACKAGE,
    TEE_PKG_AT,
};

global ROOT: [u8; 96] = [
    0x23, 0xda, 0x23, 0x71, 0x4e, 0xdf, 0x3e, 0x5b, 0x05, 0x0a, 0x3c, 0x72, 0xe8, 0x84, 0x6a, 0xce,
    0x07, 0x8e, 0xa0, 0xad, 0x1b, 0xf9, 0x8b, 0x15, 0xf4, 0x53, 0xd0, 0xcb, 0x08, 0xb2, 0xc3, 0xc1,
    0x10, 0x45, 0x39, 0x09, 0xf6, 0xed, 0xea, 0xc1, 0xf9, 0xc8, 0xe0, 0x31, 0xa8, 0x48, 0xb9, 0x41,
    0xa8, 0x29, 0x53, 0x5c, 0x97, 0xe0, 0x7c, 0x27, 0x19, 0xbe, 0xce, 0xb4, 0x16, 0x29, 0x0d, 0x30,
    0x79, 0xee, 0xe1, 0xf9, 0x11, 0xcc, 0xe6, 0xdf, 0x80, 0x39, 0x14, 0xd8, 0xa3, 0x57, 0x7b, 0x34,
    0xfd, 0xfd, 0x14, 0x3e, 0x5e, 0xf3, 0x6c, 0x97, 0x13, 0xc7, 0xac, 0x70, 0xa8, 0xc2, 0x11, 0xab,
];

/// "com.masselabs.zkproofport"
global OUR_PACKAGE: [u8; 25] = [
    0x63, 0x6f, 0x6d, 0x2e, 0x6d, 0x61, 0x73, 0x73, 0x65, 0x6c, 0x61, 0x62, 0x73, 0x2e, 0x7a, 0x6b,
    0x70, 0x72, 0x6f, 0x6f, 0x66, 0x70, 0x6f, 0x72, 0x74,
];

// 2026-03-01 00:00:00 UTC: inside the TEE chain's attestation-key
// certificate (2026-02-22 00:06:17 .. 2026-03-08 00:26:00), CA3
// (2026-02-19 .. 2026-04-30) and CA2 (2026-02-09 .. 2029-02-08).
global NOW: u64 = 1772323200;
global ATT_NOT_BEFORE: u64 = 1771718777; // 2026-02-22 00:06:17
global ATT_NOT_AFTER: u64 = 1772929560; // 2026-03-08 00:26:00

fn root() -> ([u8; 48], [u8; 48]) {
    let mut x: [u8; 48] = [0; 48];
    let mut y: [u8; 48] = [0; 48];
    for i in 0..48 {
        x[i] = ROOT[i];
        y[i] = ROOT[48 + i];
    }
    (x, y)
}

fn tee() -> AndroidChain {
    AndroidChain {
        ca2_tbs: TEE_CA2_TBS,
        ca2_tbs_len: TEE_CA2_TBS_LEN,
        ca2_sig: TEE_CA2_SIG,
        ca3_tbs: TEE_CA3_TBS,
        ca3_tbs_len: TEE_CA3_TBS_LEN,
        ca3_sig: TEE_CA3_SIG,
        att_tbs: TEE_ATT_TBS,
        att_tbs_len: TEE_ATT_TBS_LEN,
        att_sig: TEE_ATT_SIG,
        leaf_tbs: TEE_LEAF_TBS,
        leaf_tbs_len: TEE_LEAF_TBS_LEN,
        leaf_sig: TEE_LEAF_SIG,
    }
}

fn strongbox() -> AndroidChain {
    AndroidChain {
        ca2_tbs: SB_CA2_TBS,
        ca2_tbs_len: SB_CA2_TBS_LEN,
        ca2_sig: SB_CA2_SIG,
        ca3_tbs: SB_CA3_TBS,
        ca3_tbs_len: SB_CA3_TBS_LEN,
        ca3_sig: SB_CA3_SIG,
        att_tbs: SB_ATT_TBS,
        att_tbs_len: SB_ATT_TBS_LEN,
        att_sig: SB_ATT_SIG,
        leaf_tbs: SB_LEAF_TBS,
        leaf_tbs_len: SB_LEAF_TBS_LEN,
        leaf_sig: SB_LEAF_SIG,
    }
}

fn key_of(k: ([u8; 32], [u8; 32])) -> [u8; 64] {
    let mut out: [u8; 64] = [0; 64];
    for i in 0..32 {
        out[i] = k.0[i];
        out[32 + i] = k.1[i];
    }
    out
}

// ---- the real chains verify -------------------------------------------------

#[test]
fn a_real_tee_chain_verifies_for_its_own_app() {
    let (x, y) = root();
    let k = android_signing_key(tee(), x, y, TEE_PACKAGE, TEE_DIGEST, NOW);
    assert(key_of(k) == TEE_LEAF_KEY);
}

#[test]
fn a_real_strongbox_chain_verifies_for_its_own_app() {
    let (x, y) = root();
    // The StrongBox attestation key is valid 2026-02-25 .. 2026-03-06.
    let k = android_signing_key(strongbox(), x, y, SB_PACKAGE, SB_DIGEST, NOW);
    assert(key_of(k) == SB_LEAF_KEY);
}

#[test]
fn the_first_and_last_valid_seconds_are_accepted() {
    let (x, y) = root();
    let _ = android_signing_key(tee(), x, y, TEE_PACKAGE, TEE_DIGEST, ATT_NOT_BEFORE);
    let _ = android_signing_key(tee(), x, y, TEE_PACKAGE, TEE_DIGEST, ATT_NOT_AFTER);
}

// ---- whose key -------------------------------------------------------------

#[test(should_fail_with = "Key belongs to another app")]
fn a_real_chain_for_another_app_is_not_ours() {
    let (x, y) = root();
    let _ = android_signing_key(tee(), x, y, OUR_PACKAGE, TEE_DIGEST, NOW);
}

#[test(should_fail_with = "App is signed with another certificate")]
fn the_right_package_with_another_signing_certificate_is_refused() {
    let (x, y) = root();
    let mut digest = TEE_DIGEST;
    digest[31] ^= 1;
    let _ = android_signing_key(tee(), x, y, TEE_PACKAGE, digest, NOW);
}

// ---- when ----------------------------------------------------------------------

#[test(should_fail_with = "Certificate has expired at now")]
fn one_second_after_the_attestation_key_expires_is_refused() {
    let (x, y) = root();
    let _ = android_signing_key(tee(), x, y, TEE_PACKAGE, TEE_DIGEST, ATT_NOT_AFTER + 1);
}

#[test(should_fail_with = "Certificate is not valid yet at now")]
fn one_second_before_the_attestation_key_is_issued_is_refused() {
    let (x, y) = root();
    let _ = android_signing_key(tee(), x, y, TEE_PACKAGE, TEE_DIGEST, ATT_NOT_BEFORE - 1);
}

// ---- who signed ------------------------------------------------------------------

#[test(should_fail_with = "Droid CA2 is not signed by the pinned Google root")]
fn another_root_is_refused() {
    // A real P-384 key that is not the root: Droid CA2's own.
    let ca2 = walk_tbs(TEE_CA2_TBS, TEE_CA2_TBS_LEN, SIG_ALG_ECDSA_SHA384, false);
    let (x, y) = p384_key(TEE_CA2_TBS, ca2);
    let _ = android_signing_key(tee(), x, y, TEE_PACKAGE, TEE_DIGEST, NOW);
}

#[test(should_fail_with = "Droid CA2 is not signed by the pinned Google root")]
fn a_changed_ca2_is_refused() {
    let (x, y) = root();
    let mut c = tee();
    c.ca2_tbs[100] ^= 1;
    let _ = android_signing_key(c, x, y, TEE_PACKAGE, TEE_DIGEST, NOW);
}

#[test(should_fail_with = "Droid CA3 is not signed by Droid CA2")]
fn a_changed_ca3_is_refused() {
    let (x, y) = root();
    let mut c = tee();
    c.ca3_tbs[100] ^= 1;
    let _ = android_signing_key(c, x, y, TEE_PACKAGE, TEE_DIGEST, NOW);
}

#[test(should_fail_with = "Attestation key certificate is not signed by Droid CA3")]
fn a_changed_attestation_key_certificate_is_refused() {
    let (x, y) = root();
    let mut c = tee();
    c.att_tbs[100] ^= 1;
    let _ = android_signing_key(c, x, y, TEE_PACKAGE, TEE_DIGEST, NOW);
}

#[test(should_fail_with = "Leaf certificate is not signed by the attestation key")]
fn a_changed_leaf_is_refused() {
    let (x, y) = root();
    let mut c = tee();
    c.leaf_tbs[TEE_LOCKED] = 0; // unlock the bootloader in the signed bytes
    let _ = android_signing_key(c, x, y, TEE_PACKAGE, TEE_DIGEST, NOW);
}

#[test(should_fail_with = "Leaf certificate is not signed by the attestation key")]
fn another_devices_leaf_is_refused() {
    // The StrongBox leaf under the TEE chain's attestation key.
    let (x, y) = root();
    let mut c = tee();
    c.leaf_tbs = SB_LEAF_TBS;
    c.leaf_tbs_len = SB_LEAF_TBS_LEN;
    c.leaf_sig = SB_LEAF_SIG;
    let _ = android_signing_key(c, x, y, TEE_PACKAGE, TEE_DIGEST, NOW);
}

#[test(should_fail_with = "Droid CA3 is not signed by Droid CA2")]
fn the_chain_shifted_by_one_is_refused() {
    // The attestation-key certificate where CA3 belongs: a chain with one
    // intermediate fewer cannot be fed in its place.
    let (x, y) = root();
    let mut c = tee();
    let mut ca3: [u8; 768] = [0; 768];
    for i in 0..512 {
        ca3[i] = TEE_ATT_TBS[i];
    }
    c.ca3_tbs = ca3;
    c.ca3_tbs_len = TEE_ATT_TBS_LEN;
    let _ = android_signing_key(c, x, y, TEE_PACKAGE, TEE_DIGEST, NOW);
}

#[test(should_fail_with = "Leaf certificate is not signed by the attestation key")]
fn a_high_s_leaf_signature_is_refused() {
    // n - s: the same ECDSA signature, refused in its high form.
    let (x, y) = root();
    let mut c = tee();
    let n: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];
    let mut borrow: i16 = 0;
    for j in 0..32 {
        let i = 31 - j;
        let mut d = (n[i] as i16) - (c.leaf_sig[32 + i] as i16) - borrow;
        borrow = 0;
        if d < 0 {
            d += 256;
            borrow = 1;
        }
        c.leaf_sig[32 + i] = d as u8;
    }
    let _ = android_signing_key(c, x, y, TEE_PACKAGE, TEE_DIGEST, NOW);
}

#[test(should_fail_with = "No Android key attestation chain")]
fn an_empty_chain_is_refused() {
    let (x, y) = root();
    let mut c = tee();
    c.leaf_tbs_len = 0;
    let _ = android_signing_key(c, x, y, TEE_PACKAGE, TEE_DIGEST, NOW);
}

#[test(should_fail_with = "Certificate TBS padding is not zero")]
fn bytes_after_the_leaf_are_refused() {
    let (x, y) = root();
    let mut c = tee();
    c.leaf_tbs[TEE_LEAF_TBS_LEN] = 1;
    let _ = android_signing_key(c, x, y, TEE_PACKAGE, TEE_DIGEST, NOW);
}

// ---- what the key description says (real leaf, one byte changed) ------------

fn kd(leaf: [u8; 1024]) {
    let _ = check_key_description(leaf, TEE_KA_AT, TEE_KA_LEN, TEE_PACKAGE, TEE_DIGEST);
}

#[test]
fn the_real_key_description_passes() {
    kd(TEE_LEAF_TBS);
    let _ = check_key_description(SB_LEAF_TBS, SB_KA_AT, SB_KA_LEN, SB_PACKAGE, SB_DIGEST);
}

#[test(should_fail_with = "Key is not in secure hardware")]
fn a_software_key_is_refused() {
    let mut t = TEE_LEAF_TBS;
    t[TEE_ATT_LEVEL] = 0;
    t[TEE_KM_LEVEL] = 0;
    kd(t);
}

#[test(should_fail_with = "KeyMint and attestation security levels differ")]
fn a_software_keymint_under_a_tee_attestation_is_refused() {
    let mut t = TEE_LEAF_TBS;
    t[TEE_KM_LEVEL] = 0;
    kd(t);
}

#[test(should_fail_with = "Key is not in secure hardware")]
fn security_level_3_is_refused() {
    let mut t = TEE_LEAF_TBS;
    t[TEE_ATT_LEVEL] = 3;
    t[TEE_KM_LEVEL] = 3;
    kd(t);
}

#[test(should_fail_with = "Device bootloader is unlocked")]
fn an_unlocked_bootloader_is_refused() {
    let mut t = TEE_LEAF_TBS;
    t[TEE_LOCKED] = 0;
    kd(t);
}

#[test]
fn a_ber_true_for_locked_is_still_locked() {
    let mut t = TEE_LEAF_TBS;
    t[TEE_LOCKED] = 1;
    kd(t);
}

#[test(should_fail_with = "Device boot state is not Verified")]
fn a_self_signed_boot_is_refused() {
    let mut t = TEE_LEAF_TBS;
    t[TEE_BOOT_STATE] = 1;
    kd(t);
}

#[test(should_fail_with = "Device boot state is not Verified")]
fn an_unverified_boot_is_refused() {
    let mut t = TEE_LEAF_TBS;
    t[TEE_BOOT_STATE] = 2;
    kd(t);
}

#[test(should_fail_with = "Device boot state is not Verified")]
fn a_failed_boot_is_refused() {
    let mut t = TEE_LEAF_TBS;
    t[TEE_BOOT_STATE] = 3;
    kd(t);
}

#[test(should_fail_with = "Key was not generated in secure hardware")]
fn an_imported_key_is_refused() {
    let mut t = TEE_LEAF_TBS;
    t[TEE_ORIGIN] = 2;
    kd(t);
}

#[test(should_fail_with = "Key belongs to another app")]
fn one_changed_package_byte_is_refused() {
    let mut t = TEE_LEAF_TBS;
    t[TEE_PKG_AT] ^= 1;
    kd(t);
}

#[test(should_fail_with = "App is signed with another certificate")]
fn one_changed_digest_byte_is_refused() {
    let mut t = TEE_LEAF_TBS;
    t[TEE_DIGEST_AT + 31] ^= 1;
    kd(t);
}

#[test(should_fail_with = "Key belongs to another app")]
fn a_package_that_is_a_prefix_of_ours_is_refused() {
    // Our package's first 24 bytes, against a 30-byte package in the leaf.
    let mut short: [u8; 24] = [0; 24];
    for i in 0..24 {
        short[i] = TEE_PACKAGE[i];
    }
    let _ = check_key_description(TEE_LEAF_TBS, TEE_KA_AT, TEE_KA_LEN, short, TEE_DIGEST);
}

#[test(should_fail_with = "Key description length mismatch")]
fn a_key_description_read_short_is_refused() {
    let _ = check_key_description(
        TEE_LEAF_TBS,
        TEE_KA_AT,
        TEE_KA_LEN - 1,
        TEE_PACKAGE,
        TEE_DIGEST,
    );
}

#[test(should_fail_with = "Certificate TBS longer than the circuit allows")]
fn a_length_past_the_array_is_refused_by_name() {
    let (x, y) = root();
    let mut c = tee();
    c.leaf_tbs_len = 1025;
    let _ = android_signing_key(c, x, y, TEE_PACKAGE, TEE_DIGEST, NOW);
}

// ---- factory-provisioned chains (Google's RSA root) --------------------------

fn sony() -> FactoryChain {
    FactoryChain {
        ik_tbs: SONY_IK_TBS,
        ik_tbs_len: SONY_IK_TBS_LEN,
        ik_sig: SONY_IK_SIG,
        batch_tbs: SONY_BATCH_TBS,
        batch_tbs_len: SONY_BATCH_TBS_LEN,
        batch_sig: SONY_BATCH_SIG,
        leaf_tbs: SONY_LEAF_TBS,
        leaf_tbs_len: SONY_LEAF_TBS_LEN,
        leaf_sig: SONY_LEAF_SIG,
    }
}

fn blueline() -> FactoryChain {
    FactoryChain {
        ik_tbs: BLUELINE_IK_TBS,
        ik_tbs_len: BLUELINE_IK_TBS_LEN,
        ik_sig: BLUELINE_IK_SIG,
        batch_tbs: BLUELINE_BATCH_TBS,
        batch_tbs_len: BLUELINE_BATCH_TBS_LEN,
        batch_sig: BLUELINE_BATCH_SIG,
        leaf_tbs: BLUELINE_LEAF_TBS,
        leaf_tbs_len: BLUELINE_LEAF_TBS_LEN,
        leaf_sig: BLUELINE_LEAF_SIG,
    }
}

#[test]
fn a_real_sony_factory_chain_verifies_for_its_own_app() {
    let k = android_factory_signing_key(
        sony(),
        RSA_ROOT_MODULUS,
        RSA_ROOT_REDC,
        SONY_PACKAGE,
        SONY_DIGEST,
    );
    assert(key_of(k) == SONY_LEAF_KEY);
}

// A REAL refusal: Google's Pixel 3 test device has an unlocked bootloader.
// Every certificate verifies; its own key description refuses it.
#[test(should_fail_with = "Device bootloader is unlocked")]
fn a_real_pixel_3_with_an_unlocked_bootloader_is_refused() {
    let _ = android_factory_signing_key(
        blueline(),
        RSA_ROOT_MODULUS,
        RSA_ROOT_REDC,
        BLUELINE_PACKAGE,
        BLUELINE_DIGEST,
    );
}

#[test(should_fail_with = "Key belongs to another app")]
fn a_real_factory_chain_is_not_ours() {
    let _ = android_factory_signing_key(
        sony(),
        RSA_ROOT_MODULUS,
        RSA_ROOT_REDC,
        OUR_PACKAGE,
        SONY_DIGEST,
    );
}

// noir_rsa asserts inside its padding comparison, so the refusal carries no
// message of ours; the circuit acceptance runs check it the same way.
#[test(should_fail)]
fn a_changed_factory_intermediate_is_refused() {
    let mut c = sony();
    c.ik_tbs[100] ^= 1;
    let _ = android_factory_signing_key(
        c,
        RSA_ROOT_MODULUS,
        RSA_ROOT_REDC,
        SONY_PACKAGE,
        SONY_DIGEST,
    );
}

#[test(should_fail_with = "Batch certificate is not signed by the intermediate")]
fn a_changed_batch_certificate_is_refused() {
    let mut c = sony();
    c.batch_tbs[100] ^= 1;
    let _ = android_factory_signing_key(
        c,
        RSA_ROOT_MODULUS,
        RSA_ROOT_REDC,
        SONY_PACKAGE,
        SONY_DIGEST,
    );
}

#[test(should_fail_with = "Leaf certificate is not signed by the batch key")]
fn another_devices_leaf_under_this_batch_key_is_refused() {
    let mut c = sony();
    c.leaf_tbs = BLUELINE_LEAF_TBS;
    c.leaf_tbs_len = BLUELINE_LEAF_TBS_LEN;
    c.leaf_sig = BLUELINE_LEAF_SIG;
    let _ = android_factory_signing_key(
        c,
        RSA_ROOT_MODULUS,
        RSA_ROOT_REDC,
        SONY_PACKAGE,
        SONY_DIGEST,
    );
}

#[test(should_fail_with = "Batch certificate is not signed by the intermediate")]
fn another_intermediate_is_refused() {
    // Pixel 3's batch certificate under Sony's intermediate.
    let mut c = sony();
    c.batch_tbs = BLUELINE_BATCH_TBS;
    c.batch_tbs_len = BLUELINE_BATCH_TBS_LEN;
    c.batch_sig = BLUELINE_BATCH_SIG;
    let _ = android_factory_signing_key(
        c,
        RSA_ROOT_MODULUS,
        RSA_ROOT_REDC,
        SONY_PACKAGE,
        SONY_DIGEST,
    );
}

#[test(should_fail_with = "Certificate TBS longer than the circuit allows")]
fn a_factory_length_past_the_array_is_refused_by_name() {
    let mut c = sony();
    c.ik_tbs_len = 513;
    let _ = android_factory_signing_key(
        c,
        RSA_ROOT_MODULUS,
        RSA_ROOT_REDC,
        SONY_PACKAGE,
        SONY_DIGEST,
    );
}

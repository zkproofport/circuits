// A statement signed by a key this project trusts: the phone (Apple App
// Attest) or the AI server (Cloud KMS). Shared by every circuit that relies on
// such a statement -- coinbase_attestation v2 (the Coinbase attestation was
// unrevoked) and oidc_domain_attestation (the RSA key a token was checked
// with is the provider's published key).
//
// TWO SIGNERS, ONE CHECK, AND THE PROOF DOES NOT SAY WHICH
//
//   app     The phone. Apple App Attest: App Attest intermediate ->
//           credential certificate for our App ID -> an assertion over the
//           statement. The INTERMEDIATE's key ("Apple App Attestation CA 1",
//           valid to 2030-03-13) is pinned (apple_ca.nr), not Apple's root:
//           verifying root -> intermediate in-circuit costs 669,935 gates and
//           doubles a circuit to 2^21 (decided 2026-10-27,
//           .claude/agents/circuits-dev.md). When Apple issues a new
//           intermediate, every circuit using this library needs a release.
//   server  The AI server, which proves for SDK/MCP callers and has no
//           Secure Enclave. Its P-256 key (Cloud KMS) is pinned in
//           server_key.nr and signs SHA256(statement) directly.
//
// The signer kind is a PRIVATE byte. Both kinds end in the same P-256
// signature check; they differ only in where the key and the digest come
// from. A prover cannot pick their own key: the server key is a constant and
// the app key must come out of a credential certificate the pinned Apple
// intermediate signed.
//
// The app-only checks sit inside `if kind == app { ... }`. Noir compiles that
// into constraints that hold only when the condition is true (they cost the
// same either way), so the server passes zeros for every App Attest input
// instead of a dummy certificate chain.
//
// ONE KEY, MANY STATEMENTS: DOMAIN SEPARATION IS THE CALLER'S JOB
//
// The same device key and the same server key sign every kind of statement,
// so a statement must say what it is: each circuit's statement starts with
// its own 16-byte magic, then keccak256(<circuit id>), and has its own fixed
// length, and each circuit asserts all three before calling this. A signature
// over one kind can then only satisfy another kind's circuit by a SHA-256
// collision. The magics in use:
//   "ZKProofport/AA/1"  coinbase_attestation, 225 bytes (attestation unrevoked)
//   "ZKProofport/PK/1"  oidc_domain_attestation, 313 bytes (provider key)
//
// THE THIRD SIGNER: AN ANDROID PHONE, IN ITS OWN CIRCUIT PACKAGES
//
// verify_statement_android below is the Android phone: a P-256 key generated
// in secure hardware by our app (as Google Play signs it) on a device with a
// locked bootloader and verified boot, proven by Android key attestation
// under Google's Key Attestation CA1 root (../android-key-attestation). It
// signs the SAME statements (same magic, tag, length) with SHA256withECDSA.
// It is not a third `signer_kind` here: its chain costs 1,167,923 gates
// (2^21), and a kind is paid by every proof of a circuit whether used or not,
// so the iPhone and server proofs would grow from 2^20. The Android signer
// is used by separate packages (oidc-domain-attestation-android,
// coinbase-attestation-v2-android) that serve the same circuit ids.

pub mod apple_ca;
pub mod server_key;
pub mod android_root;
pub mod play_key;
mod tests;

pub use app_attest::{
    ASSERT_AUTH_DATA_MAX_LEN, ATT_AUTH_DATA_MAX_LEN, CREDENTIAL_TBS_MAX_LEN, CredentialChain,
};
use android_root::{GOOGLE_KEY_ATTESTATION_ROOT, GOOGLE_RSA_ROOT_HASH};
use app_attest::app_attest_signing_key_under_ca;
use apple_ca::APPLE_APP_ATTESTATION_CA_KEY;
use play_key::PLAY_INTEGRITY_KEY_HASH;
use server_key::SERVER_KEY;
pub use android_key_attestation::{
    AndroidChain, ATT_TBS_MAX_LEN, BATCH_TBS_MAX_LEN, CA2_TBS_MAX_LEN, CA3_TBS_MAX_LEN,
    FactoryChain, IK_TBS_MAX_LEN, LEAF_TBS_MAX_LEN, RSA4096_LIMBS,
};
use android_key_attestation::{android_factory_signing_key, android_signing_key};
pub use play_integrity::{IntegrityToken, PAYLOAD_B64_MAX_LEN};
use play_integrity::verify_integrity_token;

/// The private signer-kind byte. Any other value is refused.
pub global KIND_APP: u8 = 1;
pub global KIND_SERVER: u8 = 2;

/// Only production App Attest keys are accepted. Development (sandbox) keys
/// chain to the same Apple intermediate and differ only in the AAGUID, so this is
/// the check that keeps them out. Apple: builds distributed through
/// TestFlight / the App Store use production regardless of the entitlement,
/// and a development build can be pointed at production by setting
/// com.apple.developer.devicecheck.appattest-environment to "production".
global APP_ATTEST_PRODUCTION: bool = true;

/// The App ID: team id (proofport-app/ios DEVELOPMENT_TEAM) . bundle id.
global APP_ID: [u8; 36] = [
    0x52, 0x34, 0x47, 0x33, 0x32, 0x43, 0x56, 0x59, 0x32, 0x39, 0x2e, 0x63, 0x6f, 0x6d, 0x2e, 0x6d,
    0x61, 0x73, 0x73, 0x65, 0x6c, 0x61, 0x62, 0x73, 0x2e, 0x7a, 0x6b, 0x70, 0x72, 0x6f, 0x6f, 0x66,
    0x70, 0x6f, 0x72, 0x74,
]; // "R4G32CVY29.com.masselabs.zkproofport"

/// SHA256(APP_ID): the RP ID hash in App Attest authenticator data.
global APP_ID_HASH: [u8; 32] = [
    0x6b, 0x26, 0x19, 0x1f, 0x2b, 0x69, 0xdc, 0x7f, 0xb7, 0xee, 0x29, 0x2a, 0x73, 0x29, 0xa3, 0x5e,
    0x31, 0x45, 0xef, 0x69, 0x80, 0xbd, 0x54, 0x9d, 0x2c, 0x61, 0x2e, 0x2c, 0x2f, 0x70, 0x7b, 0xe9,
];

/// Everything a device sends below the pinned intermediate. The server kind
/// passes zeros for all of it.
pub type SignerChain = CredentialChain<CREDENTIAL_TBS_MAX_LEN, ATT_AUTH_DATA_MAX_LEN, ASSERT_AUTH_DATA_MAX_LEN>;

/// Asserts that `statement_sig` (P-256 r || s, s in low form) is
///   server: the pinned server key's signature over SHA256(statement), or
///   app:    an App Attest assertion over `statement` by a credential key the
///           pinned Apple intermediate certified for our App ID, production
///           environment.
/// The caller checks the statement's content (magic, circuit tag, fields)
/// first; this checks only who signed it.
pub fn verify_statement<let N: u32>(
    statement: [u8; N],
    signer_kind: u8,
    statement_sig: [u8; 64],
    chain: SignerChain,
) {
    assert(
        (signer_kind == KIND_APP) | (signer_kind == KIND_SERVER),
        "Unknown statement signer kind",
    );
    let statement_hash = sha256::digest(statement);

    // Server: the pinned key over SHA256(statement).
    let mut key_x: [u8; 32] = [0; 32];
    let mut key_y: [u8; 32] = [0; 32];
    for i in 0..32 {
        key_x[i] = SERVER_KEY[i];
        key_y[i] = SERVER_KEY[32 + i];
    }
    let mut digest = statement_hash;

    // App: the credential key Apple's chain vouches for, over Apple's
    // assertion digest SHA256(SHA256(authenticatorData || SHA256(statement))).
    if signer_kind == KIND_APP {
        let mut ca_x: [u8; 48] = [0; 48];
        let mut ca_y: [u8; 48] = [0; 48];
        for i in 0..48 {
            ca_x[i] = APPLE_APP_ATTESTATION_CA_KEY[i];
            ca_y[i] = APPLE_APP_ATTESTATION_CA_KEY[48 + i];
        }
        let (x, y, d, _counter) = app_attest_signing_key_under_ca(
            chain,
            ca_x,
            ca_y,
            APP_ID,
            APP_ID_HASH,
            APP_ATTEST_PRODUCTION,
            statement_hash,
        );
        key_x = x;
        key_y = y;
        digest = d;
    }

    // One P-256 check for both kinds (a Barretenberg black box; it refuses a
    // high s, so the signer's s is put in low form before proving).
    assert(
        std::ecdsa_secp256r1::verify_signature(key_x, key_y, statement_sig, digest),
        "Statement signature is invalid",
    );
}

/// The Play app signing certificate's SHA-256, as Android reports it in the
/// key attestation (attestationApplicationId.signature_digests): Play
/// re-signs every release with this key, so only store-installed builds of
/// the app match. Read 2026-10-28 from the Play Developer API
/// (generatedApks/10301 certificateSha256Hash). Debug builds and the upload
/// key do not match and are refused.
global ANDROID_SIGNING_DIGEST: [u8; 32] = [
    0xc3, 0x9b, 0x40, 0x71, 0x87, 0xd8, 0x4c, 0xe5, 0x9e, 0x90, 0xbe, 0x7f, 0xcd, 0x0b, 0xe8, 0x34,
    0xa2, 0x26, 0x78, 0x2c, 0x24, 0x02, 0x57, 0x10, 0x2f, 0x1d, 0x0a, 0x88, 0x16, 0xc6, 0x93, 0x1f,
];

/// The Android package name (proofport-app/android applicationId).
global ANDROID_PACKAGE: [u8; 25] = [
    0x63, 0x6f, 0x6d, 0x2e, 0x6d, 0x61, 0x73, 0x73, 0x65, 0x6c, 0x61, 0x62, 0x73, 0x2e, 0x7a, 0x6b,
    0x70, 0x72, 0x6f, 0x6f, 0x66, 0x70, 0x6f, 0x72, 0x74,
]; // "com.masselabs.zkproofport"

/// Asserts that `statement_sig` (P-256 r || s, s in low form) is the
/// signature, over SHA256(statement), of a key Android key attestation
/// vouches for: generated in TEE or StrongBox by our package signed with
/// Play's certificate, on a locked, verified-boot device, under a Remote Key
/// Provisioning chain from Google's Key Attestation CA1 whose certificates
/// are valid at `now` (the statement's own time). The caller checks the
/// statement's content first, as for verify_statement.
pub fn verify_statement_android<let N: u32>(
    statement: [u8; N],
    statement_sig: [u8; 64],
    chain: AndroidChain,
    now: u64,
) {
    let mut root_x: [u8; 48] = [0; 48];
    let mut root_y: [u8; 48] = [0; 48];
    for i in 0..48 {
        root_x[i] = GOOGLE_KEY_ATTESTATION_ROOT[i];
        root_y[i] = GOOGLE_KEY_ATTESTATION_ROOT[48 + i];
    }
    let (key_x, key_y) = android_signing_key(
        chain,
        root_x,
        root_y,
        ANDROID_PACKAGE,
        ANDROID_SIGNING_DIGEST,
        now,
    );
    let d = sha256::digest(statement);
    assert(
        std::ecdsa_secp256r1::verify_signature(key_x, key_y, statement_sig, d),
        "Statement signature is invalid",
    );
}

/// The Play Integrity nonce for a statement, as zkPassport builds it
/// (AppAttestModule.kt getNonceData): SHA256(SHA256(statement) || r || s),
/// with the key's signature in the low-s form the circuit takes. The app
/// requests the verdict only after signing, so the verdict is for this
/// statement and this signature.
pub fn play_integrity_nonce<let N: u32>(statement: [u8; N], statement_sig: [u8; 64]) -> [u8; 32] {
    let h = sha256::digest(statement);
    let mut pre: [u8; 96] = [0; 96];
    for i in 0..32 {
        pre[i] = h[i];
    }
    for i in 0..64 {
        pre[32 + i] = statement_sig[i];
    }
    sha256::digest(pre)
}

/// The Android signer on a FACTORY-provisioned device (launched with Android
/// 12 or earlier): Google's RSA root -> intermediate -> batch -> leaf
/// (android_factory_signing_key), the leaf key's SHA256withECDSA signature
/// over SHA256(statement), and -- because a factory key may have leaked and a
/// circuit cannot read Google's revocation list -- a Play Integrity verdict
/// (../play-integrity) signed with our app's pinned verification key
/// (play_key.nr): PLAY_RECOGNIZED, device integrity, our package, nonce =
/// play_integrity_nonce(statement, statement_sig). zkPassport's Android
/// FaceMatch circuit pairs the same two proofs. Remote Key Provisioning
/// devices use verify_statement_android, with no verdict and no server.
pub fn verify_statement_android_factory<let N: u32>(
    statement: [u8; N],
    statement_sig: [u8; 64],
    chain: FactoryChain,
    token: IntegrityToken,
    root_modulus: [u128; RSA4096_LIMBS],
    root_redc: [u128; RSA4096_LIMBS],
    play_key: [u8; 64],
) {
    // The modulus and Barrett parameter are prover inputs pinned by a hash,
    // not circuit constants: with them as constants Barretenberg's circuit
    // builder fails on noir-bignum's constant arithmetic (bb gates/write_vk:
    // "remainder_1024.lo == 0", 2026-10-28), and comparing limb by limb lets
    // the compiler fold them back into constants.
    assert(
        rsa_root_hash(root_modulus, root_redc) == GOOGLE_RSA_ROOT_HASH,
        "RSA root is not Google's",
    );
    let (key_x, key_y) = android_factory_signing_key(
        chain,
        root_modulus,
        root_redc,
        ANDROID_PACKAGE,
        ANDROID_SIGNING_DIGEST,
    );
    let statement_digest = sha256::digest(statement);
    assert(
        std::ecdsa_secp256r1::verify_signature(key_x, key_y, statement_sig, statement_digest),
        "Statement signature is invalid",
    );
    // A prover input pinned by its hash, like the RSA root: Barretenberg's
    // builder fails on an ECDSA check whose public key is a circuit constant
    // (measured 2026-10-28, same "remainder_1024" assertion).
    assert(
        play_key_hash(play_key) == PLAY_INTEGRITY_KEY_HASH,
        "Play Integrity key is not our app's",
    );
    let mut play_x: [u8; 32] = [0; 32];
    let mut play_y: [u8; 32] = [0; 32];
    for i in 0..32 {
        play_x[i] = play_key[i];
        play_y[i] = play_key[32 + i];
    }
    verify_integrity_token(
        token,
        play_x,
        play_y,
        ANDROID_PACKAGE,
        play_integrity_nonce(statement, statement_sig),
    );
}

/// Poseidon2 over the 70 limbs (modulus, then Barrett parameter).
pub fn rsa_root_hash(modulus: [u128; RSA4096_LIMBS], redc: [u128; RSA4096_LIMBS]) -> Field {
    let mut fields: [Field; 2 * RSA4096_LIMBS] = [0; 2 * RSA4096_LIMBS];
    for i in 0..RSA4096_LIMBS {
        fields[i] = modulus[i] as Field;
        fields[RSA4096_LIMBS + i] = redc[i] as Field;
    }
    poseidon::poseidon2::Poseidon2::hash(fields, 2 * RSA4096_LIMBS)
}

/// Poseidon2 over the key's four 16-byte big-endian chunks.
pub fn play_key_hash(key: [u8; 64]) -> Field {
    let mut fields: [Field; 4] = [0; 4];
    for c in 0..4 {
        let mut v: Field = 0;
        for i in 0..16 {
            v = v * 256 + key[16 * c + i] as Field;
        }
        fields[c] = v;
    }
    poseidon::poseidon2::Poseidon2::hash(fields, 4)
}

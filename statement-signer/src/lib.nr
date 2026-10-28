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

pub mod apple_ca;
pub mod server_key;
mod tests;

pub use app_attest::{
    ASSERT_AUTH_DATA_MAX_LEN, ATT_AUTH_DATA_MAX_LEN, CREDENTIAL_TBS_MAX_LEN, CredentialChain,
};
use app_attest::app_attest_signing_key_under_ca;
use apple_ca::APPLE_APP_ATTESTATION_CA_KEY;
use server_key::SERVER_KEY;

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

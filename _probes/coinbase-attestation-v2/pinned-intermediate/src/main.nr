// PROBE, not a circuit: coinbase_attestation_v2 with Apple's App Attest
// intermediate ("Apple App Attestation CA 1") PINNED instead of verified
// against Apple's root. Measurement only -- no fixtures, no vk, nothing
// deployed.
//
// Identical to ../../../coinbase-attestation-v2/src/main.nr (2026-10-24,
// circuits fc34588) except (PINNED = false puts the root link back and must
// reproduce v2's gate count; that is the control):
//   - the app kind trusts CA_1_KEY (a constant) and skips root -> intermediate
//     (SHA-384 of the intermediate TBS, P-384 by the root, intermediate DER
//     walk), so the intermediate_tbs / _len / _sig inputs are gone;
//   - the credential link is inlined from app_attest::app_attest_signing_key
//     so each part can be switched off;
//   - the WITH_* globals below switch parts off for the per-part breakdown,
//     and `probe_sink` keeps a switched-off part's inputs from being folded
//     away. With every WITH_* = true and APP_BRANCH = true this is the
//     pinned-intermediate circuit as it would ship.
//
// scripts/coinbase-attestation-v2/measure-pinned-intermediate.sh copies this
// directory once per switch, flips that one global, and prints `bb gates` and
// the dyadic size from `bb write_vk -t evm` (the vk's first field is
// log2 of the dyadic circuit size).

mod client_data;
mod server_key;

use keccak256::keccak256;
use coinbase_libs::eip1559_tx_parser;
use coinbase_libs::merkle;
use coinbase_libs::nullifier::verify_wallet_nullifier;
use coinbase_libs::signed_message::signed_digest;
use coinbase_libs::ethereum::{COINBASE_ATTESTER_CONTRACT, derive_address_from_pubkey};
use app_attest::{
    ASSERT_AUTH_DATA_MAX_LEN, ATT_AUTH_DATA_MAX_LEN, CREDENTIAL_TBS_MAX_LEN, INTERMEDIATE_TBS_MAX_LEN,
};
use app_attest::intermediate::{parse_intermediate_tbs, verify_intermediate_signature};
use app_attest::credential::parse_credential_tbs;
use app_attest::assertion::{assertion_digest, check_attestation_auth_data};
use bignum::bignum::BigNum;
use bignum::fields::secp384r1Fq::Secp384r1_Fq;
use bignum::fields::secp384r1Fr::Secp384r1_Fr;
use ecdsa::ecdsa::verify_secp384r1_ecdsa;
use client_data::{CLIENT_DATA_LEN, check_client_data};
use server_key::SERVER_KEY;

// ---- probe switches (measure-pinned-intermediate.sh flips one at a time) ----
/// false: the CONTROL -- verify root -> intermediate as v2 does (SHA-384 of
/// the intermediate TBS, P-384 by Apple's root, intermediate DER walk) and
/// use the key it yields. Must land on v2's own gate count, or this probe is
/// not v2 minus the root link.
global PINNED: bool = true;
/// false: the app checks run unconditionally (no `if signer_kind == app`).
global APP_BRANCH: bool = true;
/// false: no app kind at all -- the server-only circuit.
global WITH_APP: bool = true;
/// SHA-256 of the credential TBS (variable length, <= 1000 bytes).
global WITH_CRED_SHA256: bool = true;
/// ECDSA P-384 by CA 1 over that digest.
global WITH_CRED_P384: bool = true;
/// The credential TBS DER walk (key, nonce, App ID).
global WITH_CRED_DER: bool = true;
/// Attestation authData: SHA256(authData || clientDataHash) == nonce, RP ID,
/// counter 0, production AAGUID.
global WITH_ATT_AUTH_DATA: bool = true;
/// Assertion digest SHA256(SHA256(authData || SHA256(clientData))), RP ID,
/// counter > 0.
global WITH_ASSERTION_DIGEST: bool = true;
/// The 225-byte clientData field checks.
global WITH_CLIENT_DATA_CHECK: bool = true;
/// The one P-256 statement signature check.
global WITH_P256: bool = true;
/// PART 1: wallet secp256k1 signature over signed_digest (personal_sign or
/// EIP-712) and the pubkey -> address keccak.
global WITH_REQUEST_SIG: bool = true;
/// PART 2: Coinbase attestAccount tx (keccak of the unsigned tx, secp256k1 by
/// the attester, signer Merkle proof, to / selector / calldata).
global WITH_COINBASE_TX: bool = true;
/// PART 4: wallet nullifier (two keccaks).
global WITH_NULLIFIER: bool = true;

global KIND_APP: u8 = 1;
global KIND_SERVER: u8 = 2;
global APP_ATTEST_PRODUCTION: bool = true;
global ATTEST_ACCOUNT_SELECTOR: [u8; 4] = [0x56, 0xfe, 0xed, 0x5e];
global CIRCUIT_TAG: [u8; 32] = [
    0x16, 0x3f, 0xeb, 0x85, 0xbf, 0xfe, 0x62, 0x69, 0x88, 0x19, 0x7d, 0x1c, 0x5f, 0x0b, 0x70, 0xdc,
    0x10, 0xf5, 0x93, 0xd7, 0x08, 0xab, 0x0e, 0xfb, 0xcd, 0xfa, 0x06, 0x81, 0x4d, 0x28, 0x6b, 0xe2,
];
global APP_ID: [u8; 36] = [
    0x52, 0x34, 0x47, 0x33, 0x32, 0x43, 0x56, 0x59, 0x32, 0x39, 0x2e, 0x63, 0x6f, 0x6d, 0x2e, 0x6d,
    0x61, 0x73, 0x73, 0x65, 0x6c, 0x61, 0x62, 0x73, 0x2e, 0x7a, 0x6b, 0x70, 0x72, 0x6f, 0x6f, 0x66,
    0x70, 0x6f, 0x72, 0x74,
];
global APP_ID_HASH: [u8; 32] = [
    0x6b, 0x26, 0x19, 0x1f, 0x2b, 0x69, 0xdc, 0x7f, 0xb7, 0xee, 0x29, 0x2a, 0x73, 0x29, 0xa3, 0x5e,
    0x31, 0x45, 0xef, 0x69, 0x80, 0xbd, 0x54, 0x9d, 0x2c, 0x61, 0x2e, 0x2c, 0x2f, 0x70, 0x7b, 0xe9,
];

/// "Apple App Attestation CA 1" P-384 key, X || Y (valid to 2030-03-13), from
/// scripts/coinbase-attestation-v2/apple-vector.json `intermediate_key_xy`
/// (= app-attest-libs tests.nr REAL_CA_KEY, which tests verify against
/// Apple's root).
global CA_1_KEY: [u8; 96] = [
    0xae, 0x5b, 0x37, 0xa0, 0x77, 0x4d, 0x79, 0xb2, 0x35, 0x8f, 0x40, 0xe7, 0xd1, 0xf2, 0x26, 0x26,
    0xf1, 0xc2, 0x5f, 0xef, 0x17, 0x80, 0x2d, 0xea, 0xb3, 0x82, 0x6a, 0x59, 0x87, 0x4f, 0xf8, 0xd2,
    0xad, 0x15, 0x25, 0x78, 0x9a, 0xa2, 0x66, 0x04, 0x19, 0x12, 0x48, 0xb6, 0x3c, 0xb9, 0x67, 0x06,
    0x9e, 0x98, 0xd3, 0x63, 0xbd, 0x5e, 0x37, 0x0f, 0xbf, 0xa0, 0x8e, 0x32, 0x9e, 0x80, 0x73, 0xa9,
    0x85, 0xe7, 0x74, 0x6e, 0xa3, 0x59, 0xa2, 0xf6, 0x6f, 0x29, 0xdb, 0x32, 0xaf, 0x45, 0x5e, 0x21,
    0x16, 0x58, 0xd5, 0x67, 0xaf, 0x9e, 0x26, 0x7e, 0xb2, 0x61, 0x4d, 0xc2, 0x1a, 0x66, 0xce, 0x99,
];

/// Apple App Attestation Root CA key (= coinbase-attestation-v2/src/apple_root.nr),
/// used only by the PINNED = false control.
global APPLE_ROOT_KEY: [u8; 96] = [
    0x45, 0x31, 0xe1, 0x98, 0xb5, 0xb4, 0xec, 0x04, 0xda, 0x15, 0x02, 0x04, 0x57, 0x04, 0xed, 0x4f,
    0x87, 0x72, 0x72, 0xd7, 0x61, 0x35, 0xb2, 0x61, 0x16, 0xcf, 0xc8, 0x8b, 0x61, 0x5d, 0x0a, 0x00,
    0x07, 0x19, 0xba, 0x69, 0x85, 0x8d, 0xfe, 0x77, 0xca, 0xa3, 0xb8, 0x39, 0xe0, 0x20, 0xdd, 0xd6,
    0x56, 0x14, 0x14, 0x04, 0x70, 0x28, 0x31, 0xe4, 0x3f, 0x70, 0xb8, 0x8f, 0xd6, 0xc3, 0x94, 0xb6,
    0x08, 0xea, 0x2b, 0xd6, 0xae, 0x61, 0xe9, 0xf5, 0x98, 0xc1, 0x2f, 0x46, 0xaf, 0x52, 0x93, 0x72,
    0x66, 0xe5, 0x7f, 0x14, 0xeb, 0x61, 0xfe, 0xc5, 0x30, 0xf7, 0x14, 0x4f, 0x53, 0x81, 0x2e, 0x35,
];

fn fold<let N: u32>(acc: u8, bytes: [u8; N]) -> u8 {
    let mut a = acc;
    for i in 0..N {
        a ^= bytes[i];
    }
    a
}

fn main(
    signal_hash: pub [u8; 32],
    domain_separator: pub [u8; 32],
    action_hash: pub [u8; 32],
    signer_list_merkle_root: pub [u8; 32],
    scope: pub [u8; 32],
    nullifier: pub [u8; 32],
    attested_at: pub u64,

    user_address: [u8; 20],
    user_signature: [u8; 64],
    user_pubkey_x: [u8; 32],
    user_pubkey_y: [u8; 32],

    raw_transaction: [u8; 300],
    tx_length: u32,
    coinbase_attester_pubkey_x: [u8; 32],
    coinbase_attester_pubkey_y: [u8; 32],
    coinbase_signer_merkle_proof: [[u8; 32]; 8],
    coinbase_signer_leaf_index: u32,
    merkle_proof_depth: u32,

    client_data: [u8; CLIENT_DATA_LEN],
    signer_kind: u8,
    statement_sig: [u8; 64],

    credential_tbs: [u8; CREDENTIAL_TBS_MAX_LEN],
    credential_tbs_len: u32,
    credential_sig: [u8; 96],
    att_auth_data: [u8; ATT_AUTH_DATA_MAX_LEN],
    att_auth_data_len: u32,
    att_client_data_hash: [u8; 32],
    assertion_auth_data: [u8; ASSERT_AUTH_DATA_MAX_LEN],
    assertion_auth_data_len: u32,

    // Read only by the PINNED = false control (v2's root link).
    intermediate_tbs: [u8; INTERMEDIATE_TBS_MAX_LEN],
    intermediate_tbs_len: u32,
    intermediate_sig: [u8; 96],

    // Read only when WITH_APP = false: the server-only circuit takes the
    // server key as a witness equal to SERVER_KEY, because bb 4.2's
    // secp256r1 black box with an all-constant key aborts in write_vk
    // ("remainder_1024.lo == uint512_t(0)").
    probe_server_key: [u8; 64],
    probe_sink: u8,
) {
    let mut sink: u8 = 0;

    // PART 1
    let mut message_hash = signal_hash;
    if WITH_REQUEST_SIG {
        let derived_user_address = derive_address_from_pubkey(user_pubkey_x, user_pubkey_y);
        assert(derived_user_address == user_address, "User pubkey does not match address");
        message_hash = signed_digest(signal_hash, domain_separator, action_hash);
        assert(
            std::ecdsa_secp256k1::verify_signature(
                user_pubkey_x,
                user_pubkey_y,
                user_signature,
                message_hash,
            ),
            "Invalid user signature on the signed message",
        );
    } else {
        sink = fold(sink, domain_separator);
        sink = fold(sink, action_hash);
        sink = fold(sink, user_signature);
        sink = fold(sink, user_pubkey_x);
        sink = fold(sink, user_pubkey_y);
    }

    // PART 2
    if WITH_COINBASE_TX {
        let unsigned_tx_hash = eip1559_tx_parser::create_unsigned_tx_hash(raw_transaction, tx_length);
        let tx_signature = eip1559_tx_parser::extract_signature_from_tx(raw_transaction);
        let mut attester_signature: [u8; 64] = [0; 64];
        for i in 0..64 {
            attester_signature[i] = tx_signature[i];
        }
        assert(
            std::ecdsa_secp256k1::verify_signature(
                coinbase_attester_pubkey_x,
                coinbase_attester_pubkey_y,
                attester_signature,
                unsigned_tx_hash,
            ),
            "Invalid TX signature",
        );
        let derived_signer_address =
            derive_address_from_pubkey(coinbase_attester_pubkey_x, coinbase_attester_pubkey_y);
        let leaf_hash = keccak256(derived_signer_address, 20);
        let calculated_root = merkle::verify_merkle_proof(
            leaf_hash,
            coinbase_signer_leaf_index,
            coinbase_signer_merkle_proof,
            merkle_proof_depth,
        );
        assert(calculated_root == signer_list_merkle_root, "Signer not in valid list");
        let to_address = eip1559_tx_parser::extract_to_address(raw_transaction);
        assert(to_address == COINBASE_ATTESTER_CONTRACT, "TX sent to wrong contract");
        let calldata = eip1559_tx_parser::extract_calldata(raw_transaction);
        let mut selector: [u8; 4] = [0; 4];
        for i in 0..4 {
            selector[i] = calldata[i];
        }
        assert(selector == ATTEST_ACCOUNT_SELECTOR, "Invalid function selector");
        let calldata_address = eip1559_tx_parser::extract_address_from_calldata(calldata);
        assert(calldata_address == user_address, "Calldata address does not match user_address");
    } else {
        sink = fold(sink, raw_transaction);
        sink ^= tx_length as u8;
        sink ^= coinbase_signer_leaf_index as u8;
        sink ^= merkle_proof_depth as u8;
        sink = fold(sink, coinbase_attester_pubkey_x);
        sink = fold(sink, coinbase_attester_pubkey_y);
        sink = fold(sink, signer_list_merkle_root);
        for i in 0..8 {
            sink = fold(sink, coinbase_signer_merkle_proof[i]);
        }
    }

    // PART 3
    if WITH_CLIENT_DATA_CHECK {
        check_client_data(client_data, CIRCUIT_TAG, user_address, attested_at, message_hash, scope);
    } else {
        sink = fold(sink, message_hash);
        sink ^= attested_at as u8;
    }
    assert(
        (signer_kind == KIND_APP) | (signer_kind == KIND_SERVER),
        "Unknown statement signer kind",
    );
    let client_data_hash = sha256::digest(client_data);

    let mut key_x: [u8; 32] = [0; 32];
    let mut key_y: [u8; 32] = [0; 32];
    for i in 0..32 {
        key_x[i] = SERVER_KEY[i];
        key_y[i] = SERVER_KEY[32 + i];
    }
    let mut digest = client_data_hash;

    if WITH_APP {
        if (signer_kind == KIND_APP) | (!APP_BRANCH) {
            // Credential certificate signed by the PINNED CA 1 key (or, in
            // the control, by the intermediate key the root link yields).
            let mut ca_x: [u8; 48] = [0; 48];
            let mut ca_y: [u8; 48] = [0; 48];
            for i in 0..48 {
                ca_x[i] = CA_1_KEY[i];
                ca_y[i] = CA_1_KEY[48 + i];
            }
            if !PINNED {
                assert(intermediate_tbs_len != 0, "No App Attest certificate chain");
                let mut root_x: [u8; 48] = [0; 48];
                let mut root_y: [u8; 48] = [0; 48];
                let mut ir: [u8; 48] = [0; 48];
                let mut is: [u8; 48] = [0; 48];
                for i in 0..48 {
                    root_x[i] = APPLE_ROOT_KEY[i];
                    root_y[i] = APPLE_ROOT_KEY[48 + i];
                    ir[i] = intermediate_sig[i];
                    is[i] = intermediate_sig[48 + i];
                }
                assert(
                    verify_intermediate_signature(
                        root_x,
                        root_y,
                        intermediate_tbs,
                        intermediate_tbs_len,
                        ir,
                        is,
                    ),
                    "Intermediate is not signed by Apple's App Attestation root",
                );
                let ca = parse_intermediate_tbs(intermediate_tbs, intermediate_tbs_len);
                ca_x = ca.x;
                ca_y = ca.y;
            }
            let mut tbs_digest: [u8; 32] = [0; 32];
            if WITH_CRED_SHA256 {
                tbs_digest = sha256::sha256_var(credential_tbs, credential_tbs_len);
            } else {
                for i in 0..32 {
                    tbs_digest[i] = credential_tbs[i];
                }
                sink ^= credential_tbs_len as u8;
            }
            if WITH_CRED_P384 {
                let mut r: [u8; 48] = [0; 48];
                let mut s: [u8; 48] = [0; 48];
                for i in 0..48 {
                    r[i] = credential_sig[i];
                    s[i] = credential_sig[48 + i];
                }
                let px: Secp384r1_Fq = Secp384r1_Fq::from_be_bytes(ca_x);
                let py: Secp384r1_Fq = Secp384r1_Fq::from_be_bytes(ca_y);
                let rr: Secp384r1_Fr = Secp384r1_Fr::from_be_bytes(r);
                let ss: Secp384r1_Fr = Secp384r1_Fr::from_be_bytes(s);
                assert(
                    verify_secp384r1_ecdsa(px, py, tbs_digest, (rr, ss)),
                    "Credential certificate is not signed by the App Attest intermediate",
                );
            } else {
                sink = fold(sink, tbs_digest);
                sink = fold(sink, credential_sig);
            }

            let mut cred_x: [u8; 32] = [0; 32];
            let mut cred_y: [u8; 32] = [0; 32];
            let mut nonce: [u8; 32] = [0; 32];
            if WITH_CRED_DER {
                let key = parse_credential_tbs(credential_tbs, credential_tbs_len, APP_ID);
                cred_x = key.x;
                cred_y = key.y;
                nonce = key.nonce;
            } else {
                for i in 0..32 {
                    cred_x[i] = credential_tbs[100 + i];
                    cred_y[i] = credential_tbs[132 + i];
                    nonce[i] = credential_tbs[700 + i];
                }
            }

            if WITH_ATT_AUTH_DATA {
                check_attestation_auth_data(
                    att_auth_data,
                    att_auth_data_len,
                    att_client_data_hash,
                    nonce,
                    APP_ID_HASH,
                    APP_ATTEST_PRODUCTION,
                );
            } else {
                sink = fold(sink, att_auth_data);
                sink ^= att_auth_data_len as u8;
                sink = fold(sink, att_client_data_hash);
                sink = fold(sink, nonce);
            }

            let mut d = client_data_hash;
            if WITH_ASSERTION_DIGEST {
                let (ad, _counter) = assertion_digest(
                    assertion_auth_data,
                    assertion_auth_data_len,
                    client_data_hash,
                    APP_ID_HASH,
                );
                d = ad;
            } else {
                sink = fold(sink, assertion_auth_data);
                sink ^= assertion_auth_data_len as u8;
            }
            key_x = cred_x;
            key_y = cred_y;
            digest = d;
        }
    } else {
        for i in 0..32 {
            key_x[i] = probe_server_key[i];
            key_y[i] = probe_server_key[32 + i];
        }
        assert(probe_server_key == SERVER_KEY, "probe server key");
        sink = fold(sink, credential_tbs);
        sink ^= credential_tbs_len as u8;
        sink = fold(sink, credential_sig);
        sink = fold(sink, att_auth_data);
        sink ^= att_auth_data_len as u8;
        sink = fold(sink, att_client_data_hash);
        sink = fold(sink, assertion_auth_data);
        sink ^= assertion_auth_data_len as u8;
    }

    if WITH_P256 {
        assert(
            std::ecdsa_secp256r1::verify_signature(key_x, key_y, statement_sig, digest),
            "Statement signature is invalid",
        );
    } else {
        sink = fold(sink, key_x);
        sink = fold(sink, key_y);
        sink = fold(sink, statement_sig);
        sink = fold(sink, digest);
    }

    // PART 4
    if WITH_NULLIFIER {
        verify_wallet_nullifier(user_address, CIRCUIT_TAG, scope, nullifier);
    } else {
        sink = fold(sink, nullifier);
    }

    assert(sink != probe_sink, "probe sink");
}

use app_attest::{ATT_AUTH_DATA_MAX_LEN, CREDENTIAL_TBS_MAX_LEN};
use app_attest::assertion::check_attestation_auth_data;
use app_attest::credential::parse_credential_tbs;

fn main(
    ca_key: [u8; 96],
    ca_key_hash: pub [u8; 32],
    tbs: [u8; CREDENTIAL_TBS_MAX_LEN],
    tbs_len: u32,
    att_auth_data: [u8; ATT_AUTH_DATA_MAX_LEN],
    att_auth_data_len: u32,
    att_client_data_hash: [u8; 32],
    app_id: [u8; 36],
    app_id_hash: [u8; 32],
    production: bool,
) -> pub ([u8; 32], [u8; 32], [u8; 32]) {
    assert(sha256::digest(ca_key) == ca_key_hash);
    // The digest the P-384 check consumes; returned so it is not optimised away.
    let digest = sha256::sha256_var(tbs, tbs_len);
    let key = parse_credential_tbs(tbs, tbs_len, app_id);
    check_attestation_auth_data(att_auth_data, att_auth_data_len, att_client_data_hash, key.nonce, app_id_hash, production);
    (digest, key.x, key.y)
}

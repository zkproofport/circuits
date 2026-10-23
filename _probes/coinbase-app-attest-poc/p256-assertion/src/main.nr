use app_attest::ASSERT_AUTH_DATA_MAX_LEN;
use app_attest::assertion::verify_assertion;

fn main(
    key_x: [u8; 32],
    key_y: [u8; 32],
    auth_data: [u8; ASSERT_AUTH_DATA_MAX_LEN],
    auth_len: u32,
    client_data: [u8; 225],
    signature: [u8; 64],
    app_id_hash: [u8; 32],
) -> pub u32 {
    verify_assertion(key_x, key_y, auth_data, auth_len, client_data, signature, app_id_hash)
}

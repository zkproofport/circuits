// Secret header value proof, 2k tier: the hidden value is at most 2048 bytes.
// See ../zktls-secret-header-libs/src/lib.nr for what is proved.

use zktls_secret_header_libs::{BLINDER_LEN, verify_secret_value};

mod tests;

global TIER: u32 = 2048;

fn main(
    // Private: the hidden header value, zero-padded to the tier, and its blinder.
    value: [u8; TIER],
    len: u32,
    blinder: [u8; BLINDER_LEN],
    // Public: the commitment the verifier signed for this hidden range.
    commitment: pub [u8; 32],
) {
    verify_secret_value::<TIER>(value, len, blinder, commitment);
}

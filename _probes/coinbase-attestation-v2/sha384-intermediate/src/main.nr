// SHA-384 of a variable-length intermediate TBS (<= INTERMEDIATE_TBS_MAX_LEN),
// zkpassport/sha512 v0.1.1, alone.
use app_attest::INTERMEDIATE_TBS_MAX_LEN;

fn main(tbs: [u8; INTERMEDIATE_TBS_MAX_LEN], tbs_len: u32) -> pub [u8; 48] {
    sha512::sha384::sha384_var(BoundedVec::from_parts(tbs, tbs_len))
}

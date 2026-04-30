// PoC: JSON path extract + predicate evaluation + nullifier
// Schema: kakao-userinfo-age-gte-19
// Goal: measure gate count for predicate eval over plaintext
// Pattern: DECO verifiable substring (prover-supplied offsets, circuit verifies grammar)

use keccak256::keccak256;

global PT_MAX: u32 = 256;
global SUB_MAX: u32 = 64;

fn main(
    // PUBLIC INPUTS
    plaintext: pub [u8; PT_MAX],
    plaintext_len: pub u32,
    threshold_year: pub u32, // 2007 for age >= 19 in 2026
    expected_predicate: pub Field,
    expected_nullifier: pub [u8; 32],
    // PRIVATE WITNESS (prover-supplied offsets)
    birthyear_offset: u32,
    sub_offset: u32,
    sub_len: u32,
) {
    // 1. Bounds check
    assert(birthyear_offset + 4 <= plaintext_len);
    assert(sub_offset + sub_len <= plaintext_len);
    assert(sub_len <= SUB_MAX as u32);

    // 2. Extract birthyear (4 ASCII digits)
    let mut year: u32 = 0;
    for i in 0..4 {
        let digit: u8 = plaintext[birthyear_offset + (i as u32)];
        assert(digit >= 48); // '0'
        assert(digit <= 57); // '9'
        year = year * 10 + ((digit - 48) as u32);
    }

    // 3. Predicate: birthyear <= threshold_year (older = lower year)
    let predicate_bool = year <= threshold_year;
    let predicate_field: Field = predicate_bool as Field;
    assert(predicate_field == expected_predicate);

    // 4. Extract sub bytes for nullifier
    let mut sub_bytes: [u8; SUB_MAX] = [0; SUB_MAX];
    for i in 0..SUB_MAX {
        if (i as u32) < sub_len {
            sub_bytes[i] = plaintext[sub_offset + (i as u32)];
        }
    }

    // 5. Nullifier = keccak256(sub)
    let nullifier_hash: [u8; 32] = keccak256(sub_bytes, sub_len);
    for i in 0..32 {
        assert(nullifier_hash[i] == expected_nullifier[i]);
    }
}

#[test]
fn test_kakao_age_predicate() {
    let mut plaintext: [u8; PT_MAX] = [0; PT_MAX];
    // sub: "12345" at offset 0
    plaintext[0] = 0x31;
    plaintext[1] = 0x32;
    plaintext[2] = 0x33;
    plaintext[3] = 0x34;
    plaintext[4] = 0x35;
    // birthyear: "2000" at offset 10
    plaintext[10] = 0x32;
    plaintext[11] = 0x30;
    plaintext[12] = 0x30;
    plaintext[13] = 0x30;

    // Compute expected nullifier
    let mut sub_bytes: [u8; SUB_MAX] = [0; SUB_MAX];
    sub_bytes[0] = 0x31;
    sub_bytes[1] = 0x32;
    sub_bytes[2] = 0x33;
    sub_bytes[3] = 0x34;
    sub_bytes[4] = 0x35;
    let expected_nullifier: [u8; 32] = keccak256(sub_bytes, 5);

    main(
        plaintext,
        256,
        2007,
        1, // 2000 <= 2007 -> predicate true
        expected_nullifier,
        10, // birthyear_offset
        0, // sub_offset
        5, // sub_len
    );
}

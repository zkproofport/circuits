// Proofport zkTLS production circuit
// MVP: AES-256-CTR decrypt (multi-block) + zkPass-style matcher + nullifier + schema binding
//
// TEE-as-prover trust model:
//   - TLS handshake, cert chain, GCM tag verify handled by enclave's standard TLS
//   - Circuit verifies: ciphertext decrypts (with hidden key) to plaintext that satisfies schema
//   - user_data in Nitro attestation binds ciphertext to verified server
//
// Cipher: AES-256 (matches Kakao TLS_AES_256_GCM_SHA384)

use pluto_aes_gcm::aes::aes_256;
use pluto_aes_gcm::gctr::increment_32;
use pluto_aes_gcm::utils::{block_to_stream, stream_to_block};
use keccak256::keccak256;

// 8 zkPass operators (in/contains TODO)
global OP_EQ: u32 = 0;
global OP_NEQ: u32 = 1;
global OP_GT: u32 = 2;
global OP_LT: u32 = 3;
global OP_GTE: u32 = 4;
global OP_LTE: u32 = 5;

global PLAINTEXT_LEN: u32 = 256; // 16 AES blocks
global N_BLOCKS: u32 = 16;
global VAL_MAX: u32 = 32;
global SUB_MAX: u32 = 64;

fn main(
    // PRIVATE WITNESS
    aes_key: [u8; 32],
    initial_counter: [u8; 16],
    extracted_value_offset: u32,
    extracted_value_len: u32,
    sub_offset: u32,
    sub_len: u32,
    // PUBLIC INPUTS
    ciphertext: pub [u8; PLAINTEXT_LEN],
    schema_hash: pub [u8; 32],
    op_code: pub u32,
    expected_value: pub [u8; VAL_MAX],
    expected_value_len: pub u32,
    // PUBLIC OUTPUTS
    expected_predicate: pub Field,
    expected_nullifier: pub [u8; 32],
) {
    // 1. AES-256-CTR multi-block decrypt
    let mut plaintext: [u8; PLAINTEXT_LEN] = [0; PLAINTEXT_LEN];
    let mut counter = stream_to_block(initial_counter);
    for i in 0..N_BLOCKS {
        let keystream_block = aes_256(counter, aes_key);
        let keystream = block_to_stream(keystream_block);
        for j in 0..16 {
            plaintext[i * 16 + j] = ciphertext[i * 16 + j] ^ keystream[j];
        }
        counter = increment_32(counter);
    }

    // 2. Bounds
    assert(extracted_value_offset + extracted_value_len <= PLAINTEXT_LEN);
    assert(sub_offset + sub_len <= PLAINTEXT_LEN);
    assert(extracted_value_len <= VAL_MAX);
    assert(sub_len <= SUB_MAX);

    // 3. Extract value at prover-supplied offset
    let mut extracted_value: [u8; VAL_MAX] = [0; VAL_MAX];
    for i in 0..VAL_MAX {
        if (i as u32) < extracted_value_len {
            extracted_value[i] = plaintext[extracted_value_offset + (i as u32)];
        }
    }

    // 4. Operator dispatch
    let result = apply_operator(
        op_code,
        extracted_value,
        extracted_value_len,
        expected_value,
        expected_value_len,
    );
    assert(result == expected_predicate);

    // 5. Nullifier
    let mut sub_bytes: [u8; SUB_MAX] = [0; SUB_MAX];
    for i in 0..SUB_MAX {
        if (i as u32) < sub_len {
            sub_bytes[i] = plaintext[sub_offset + (i as u32)];
        }
    }
    let computed_nullifier = keccak256(sub_bytes, sub_len);
    for i in 0..32 {
        assert(computed_nullifier[i] == expected_nullifier[i]);
    }

    // 6. Schema binding (keccak256)
    // Input: op_code(1B) || expected_value(32B) || expected_value_len(4B BE)
    let mut schema_input: [u8; 37] = [0; 37];
    schema_input[0] = op_code as u8;
    for i in 0..VAL_MAX {
        schema_input[1 + i] = expected_value[i];
    }
    schema_input[33] = ((expected_value_len >> 24) & 0xff) as u8;
    schema_input[34] = ((expected_value_len >> 16) & 0xff) as u8;
    schema_input[35] = ((expected_value_len >> 8) & 0xff) as u8;
    schema_input[36] = (expected_value_len & 0xff) as u8;

    let computed_schema: [u8; 32] = keccak256(schema_input, 37);
    for i in 0..32 {
        assert(computed_schema[i] == schema_hash[i]);
    }
}

fn apply_operator<let N: u32>(
    op: u32,
    value: [u8; N],
    value_len: u32,
    expected: [u8; N],
    expected_len: u32,
) -> Field {
    let bytes_eq = bytes_equal(value, value_len, expected, expected_len);
    if op == OP_EQ {
        bytes_eq as Field
    } else if op == OP_NEQ {
        (!bytes_eq) as Field
    } else {
        let v = parse_int(value, value_len);
        let e = parse_int(expected, expected_len);
        if op == OP_GT {
            (v > e) as Field
        } else if op == OP_LT {
            (v < e) as Field
        } else if op == OP_GTE {
            (v >= e) as Field
        } else if op == OP_LTE {
            (v <= e) as Field
        } else {
            assert(false, "unsupported operator");
            0
        }
    }
}

fn bytes_equal<let N: u32>(a: [u8; N], a_len: u32, b: [u8; N], b_len: u32) -> bool {
    let mut eq = a_len == b_len;
    for i in 0..N {
        if (i as u32) < a_len {
            if a[i] != b[i] {
                eq = false;
            }
        }
    }
    eq
}

fn parse_int<let N: u32>(bytes: [u8; N], len: u32) -> u64 {
    let mut v: u64 = 0;
    for i in 0..N {
        if (i as u32) < len {
            let d = bytes[i];
            assert(d >= 48);
            assert(d <= 57);
            v = v * 10 + ((d - 48) as u64);
        }
    }
    v
}

#[test]
fn test_kakao_e2e() {
    // Simulated Kakao userinfo plaintext (256 bytes)
    // bytes 0..5  = "12345" (sub for nullifier)
    // bytes 10..14 = "2000" (birthyear for predicate)
    let mut plaintext: [u8; PLAINTEXT_LEN] = [0; PLAINTEXT_LEN];
    plaintext[0] = 0x31;
    plaintext[1] = 0x32;
    plaintext[2] = 0x33;
    plaintext[3] = 0x34;
    plaintext[4] = 0x35;
    plaintext[10] = 0x32;
    plaintext[11] = 0x30;
    plaintext[12] = 0x30;
    plaintext[13] = 0x30;

    // AES-256 key + counter (NIST CAVP CTR test vector)
    let aes_key: [u8; 32] = [
        0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77,
        0x81, 0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x6E, 0x93, 0x4D, 0x6F, 0x2C, 0x56, 0x28, 0x7E, 0x7B,
        0x5C, 0xE5,
    ];
    let initial_counter: [u8; 16] = [
        0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE,
        0xFF,
    ];

    // Compute ciphertext = AES-256-CTR(key, counter, plaintext)
    let mut ciphertext: [u8; PLAINTEXT_LEN] = [0; PLAINTEXT_LEN];
    let mut counter = stream_to_block(initial_counter);
    for i in 0..N_BLOCKS {
        let ks_block = aes_256(counter, aes_key);
        let ks = block_to_stream(ks_block);
        for j in 0..16 {
            ciphertext[i * 16 + j] = plaintext[i * 16 + j] ^ ks[j];
        }
        counter = increment_32(counter);
    }

    // Schema: op=LTE, expected_value="2007"
    let mut expected_value: [u8; VAL_MAX] = [0; VAL_MAX];
    expected_value[0] = 0x32;
    expected_value[1] = 0x30;
    expected_value[2] = 0x30;
    expected_value[3] = 0x37;

    let mut schema_input: [u8; 37] = [0; 37];
    schema_input[0] = OP_LTE as u8;
    for i in 0..VAL_MAX {
        schema_input[1 + i] = expected_value[i];
    }
    schema_input[33] = 0;
    schema_input[34] = 0;
    schema_input[35] = 0;
    schema_input[36] = 4;
    let schema_hash: [u8; 32] = keccak256(schema_input, 37);

    // Nullifier
    let mut sub_bytes: [u8; SUB_MAX] = [0; SUB_MAX];
    sub_bytes[0] = 0x31;
    sub_bytes[1] = 0x32;
    sub_bytes[2] = 0x33;
    sub_bytes[3] = 0x34;
    sub_bytes[4] = 0x35;
    let nullifier = keccak256(sub_bytes, 5);

    main(
        aes_key, initial_counter, 10, 4, 0, 5, ciphertext, schema_hash, OP_LTE, expected_value, 4,
        1, // 2000 <= 2007 -> true
        nullifier,
    );
}

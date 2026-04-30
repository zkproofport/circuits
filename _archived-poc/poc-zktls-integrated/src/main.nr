// PoC: integrated zkTLS circuit
// AES-256 decrypt + zkPass-style matcher + nullifier in single circuit
// Schema target: kakao-userinfo-age-gte-19
// Cipher: AES-256-GCM (Kakao TLS 1.3)
// MVP: TEE trust model (cert chain outside circuit)

use pluto_aes_gcm::aes::aes_256;
use keccak256::keccak256;
use poseidon::poseidon2::Poseidon2;

// 8 operators (zkPass standard)
global OP_EQ: u32 = 0;
global OP_NEQ: u32 = 1;
global OP_GT: u32 = 2;
global OP_LT: u32 = 3;
global OP_GTE: u32 = 4;
global OP_LTE: u32 = 5;

// Single TLS 1.3 record block (16 bytes plaintext)
// Real production: chain N blocks via CTR mode + single GHash
global VAL_MAX: u32 = 32;
global SUB_MAX: u32 = 64;

fn stream_to_block(s: [u8; 16]) -> [[u8; 4]; 4] {
    let mut b: [[u8; 4]; 4] = [[0; 4]; 4];
    for i in 0..4 {
        for j in 0..4 {
            b[j][i] = s[i * 4 + j];
        }
    }
    b
}

fn block_to_stream(b: [[u8; 4]; 4]) -> [u8; 16] {
    let mut s: [u8; 16] = [0; 16];
    for i in 0..4 {
        for j in 0..4 {
            s[i * 4 + j] = b[j][i];
        }
    }
    s
}

fn main(
    // TLS record (encrypted by enclave standard TLS, given to circuit)
    aes_key: [u8; 32], // PRIVATE - hidden from verifier
    counter_block: [u8; 16], // PRIVATE - CTR initial counter
    ciphertext: pub [u8; 16],
    // Schema (public - what was checked)
    schema_hash: pub Field,
    op_code: pub u32,
    expected_value: pub [u8; VAL_MAX],
    expected_value_len: pub u32,
    // Result (public output the verifier sees)
    expected_predicate: pub Field,
    expected_nullifier: pub [u8; 32],
    // Witness offsets (prover-supplied position into plaintext)
    extracted_value_offset: u32,
    extracted_value_len: u32,
    sub_offset: u32,
    sub_len: u32,
) {
    // ========================================
    // 1. AES-256-CTR decrypt (single block)
    // CTR is symmetric: encrypt(counter) XOR ciphertext = plaintext
    // Real production: chain N blocks with counter increment
    // ========================================
    let counter_block_state = stream_to_block(counter_block);
    let keystream_block = aes_256(counter_block_state, aes_key);
    let keystream = block_to_stream(keystream_block);

    let mut plaintext: [u8; 16] = [0; 16];
    for i in 0..16 {
        plaintext[i] = ciphertext[i] ^ keystream[i];
    }

    // ========================================
    // 2. Bounds checks
    // ========================================
    assert(extracted_value_offset + extracted_value_len <= 16);
    assert(sub_offset + sub_len <= 16);
    assert(extracted_value_len <= VAL_MAX);
    assert(sub_len <= SUB_MAX);

    // ========================================
    // 3. Extract value at offset
    // ========================================
    let mut extracted_value: [u8; VAL_MAX] = [0; VAL_MAX];
    for i in 0..VAL_MAX {
        if (i as u32) < extracted_value_len {
            extracted_value[i] = plaintext[extracted_value_offset + (i as u32)];
        }
    }

    // ========================================
    // 4. Operator dispatch (zkPass-style)
    // ========================================
    let result = apply_operator(
        op_code,
        extracted_value,
        extracted_value_len,
        expected_value,
        expected_value_len,
    );
    assert(result == expected_predicate);

    // ========================================
    // 5. Nullifier (keccak256 of sub field)
    // ========================================
    let mut sub_bytes: [u8; SUB_MAX] = [0; SUB_MAX];
    for i in 0..SUB_MAX {
        if (i as u32) < sub_len {
            sub_bytes[i] = plaintext[sub_offset + (i as u32)];
        }
    }
    let computed_nullifier: [u8; 32] = keccak256(sub_bytes, sub_len);
    for i in 0..32 {
        assert(computed_nullifier[i] == expected_nullifier[i]);
    }

    // ========================================
    // 6. Schema binding (poseidon hash)
    // ========================================
    let mut value_field: Field = 0;
    for i in 0..VAL_MAX {
        value_field = value_field * 256 + (expected_value[i] as Field);
    }
    let computed_schema = Poseidon2::hash([op_code as Field, value_field, expected_value_len as Field], 3);
    assert(computed_schema == schema_hash);
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
fn test_integrated_kakao() {
    // Simulate enclave-decrypted plaintext: contains "12345" at 0, "2000" at 10
    let mut plaintext: [u8; 16] = [0; 16];
    plaintext[0] = 0x31;
    plaintext[1] = 0x32;
    plaintext[2] = 0x33;
    plaintext[3] = 0x34;
    plaintext[4] = 0x35;
    plaintext[10] = 0x32;
    plaintext[11] = 0x30;
    plaintext[12] = 0x30;
    plaintext[13] = 0x30;

    // Random AES-256 key + counter
    let aes_key: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    let counter_block: [u8; 16] = [
        0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ];

    // Compute ciphertext = aes_256(counter, key) XOR plaintext
    let counter_state = stream_to_block(counter_block);
    let ks_state = aes_256(counter_state, aes_key);
    let ks = block_to_stream(ks_state);
    let mut ciphertext: [u8; 16] = [0; 16];
    for i in 0..16 {
        ciphertext[i] = plaintext[i] ^ ks[i];
    }

    // Schema: op=LTE, expected_value="2007"
    let mut expected_value: [u8; VAL_MAX] = [0; VAL_MAX];
    expected_value[0] = 0x32;
    expected_value[1] = 0x30;
    expected_value[2] = 0x30;
    expected_value[3] = 0x37;

    let mut value_field: Field = 0;
    for i in 0..VAL_MAX {
        value_field = value_field * 256 + (expected_value[i] as Field);
    }
    let schema_hash = Poseidon2::hash([OP_LTE as Field, value_field, 4], 3);

    let mut sub_bytes: [u8; SUB_MAX] = [0; SUB_MAX];
    sub_bytes[0] = 0x31;
    sub_bytes[1] = 0x32;
    sub_bytes[2] = 0x33;
    sub_bytes[3] = 0x34;
    sub_bytes[4] = 0x35;
    let nullifier = keccak256(sub_bytes, 5);

    main(
        aes_key,
        counter_block,
        ciphertext,
        schema_hash,
        OP_LTE,
        expected_value,
        4,
        1, // 2000 <= 2007
        nullifier,
        10,
        4,
        0,
        5,
    );
}

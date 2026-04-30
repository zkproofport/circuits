// PoC: zkPass-style generic schema matcher
// Goal: 1 circuit supports all schemas (operators dispatched by op_code)
// Pattern: zkPass schema-driven assert

use keccak256::keccak256;
use poseidon::poseidon2::Poseidon2;

// 8 operators (zkPass standard)
global OP_EQ: u32 = 0;
global OP_NEQ: u32 = 1;
global OP_GT: u32 = 2;
global OP_LT: u32 = 3;
global OP_GTE: u32 = 4;
global OP_LTE: u32 = 5;

global PT_MAX: u32 = 1024;
global VAL_MAX: u32 = 32;
global SUB_MAX: u32 = 64;

fn main(
    // Plaintext (recovered by AES-GCM circuit upstream)
    plaintext: pub [u8; PT_MAX],
    plaintext_len: pub u32,
    // Schema-defined (public input - verifier sees what schema was used)
    schema_hash: pub Field,
    op_code: pub u32,
    expected_value: pub [u8; VAL_MAX],
    expected_value_len: pub u32,
    // Result
    expected_predicate: pub Field,
    expected_nullifier: pub [u8; 32],
    // Private witness (prover supplies offsets)
    extracted_value_offset: u32,
    extracted_value_len: u32,
    sub_offset: u32,
    sub_len: u32,
) {
    // 1. Bounds checks
    assert(extracted_value_offset + extracted_value_len <= plaintext_len);
    assert(sub_offset + sub_len <= plaintext_len);
    assert(extracted_value_len <= VAL_MAX);
    assert(sub_len <= SUB_MAX);

    // 2. Extract value
    let mut extracted_value: [u8; VAL_MAX] = [0; VAL_MAX];
    for i in 0..VAL_MAX {
        if (i as u32) < extracted_value_len {
            extracted_value[i] = plaintext[extracted_value_offset + (i as u32)];
        }
    }

    // 3. Operator dispatch
    let result_field = apply_operator(
        op_code,
        extracted_value,
        extracted_value_len,
        expected_value,
        expected_value_len,
    );
    assert(result_field == expected_predicate);

    // 4. Nullifier from sub field
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

    // 5. Schema binding (poseidon hash of schema params)
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
        // Numeric ops: parse ASCII digits as u64
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
            // Unsupported op; force fail
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
fn test_lte_birthyear() {
    let mut plaintext: [u8; PT_MAX] = [0; PT_MAX];
    // sub: "12345" at 0
    plaintext[0] = 0x31;
    plaintext[1] = 0x32;
    plaintext[2] = 0x33;
    plaintext[3] = 0x34;
    plaintext[4] = 0x35;
    // birthyear: "2000" at 10
    plaintext[10] = 0x32;
    plaintext[11] = 0x30;
    plaintext[12] = 0x30;
    plaintext[13] = 0x30;

    // Schema: op=LTE, expected_value="2007"
    let mut expected_value: [u8; VAL_MAX] = [0; VAL_MAX];
    expected_value[0] = 0x32;
    expected_value[1] = 0x30;
    expected_value[2] = 0x30;
    expected_value[3] = 0x37;

    // Compute schema_hash
    let mut value_field: Field = 0;
    for i in 0..VAL_MAX {
        value_field = value_field * 256 + (expected_value[i] as Field);
    }
    let schema_hash = Poseidon2::hash([OP_LTE as Field, value_field, 4], 3);

    // Nullifier
    let mut sub_bytes: [u8; SUB_MAX] = [0; SUB_MAX];
    sub_bytes[0] = 0x31;
    sub_bytes[1] = 0x32;
    sub_bytes[2] = 0x33;
    sub_bytes[3] = 0x34;
    sub_bytes[4] = 0x35;
    let nullifier = keccak256(sub_bytes, 5);

    main(
        plaintext,
        PT_MAX,
        schema_hash,
        OP_LTE,
        expected_value,
        4,
        1, // 2000 <= 2007 -> true
        nullifier,
        10,
        4,
        0,
        5,
    );
}

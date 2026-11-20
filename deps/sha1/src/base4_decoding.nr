use crate::tables::{
    BASE4_ROUND1_A_DECODE_5BIT_TABLE,
    BASE4_ROUND1_B_DECODE_5BIT_TABLE, BASE4_ROUND3_DECODE_5BIT_TABLE, BASE4_XOR_DECODE_5BIT_TABLE,
};


unconstrained fn __split_into_base4_5bit_slices(encoded: Field) -> [u32; 7] {
    let mut acc = encoded as u128;

    assert_eq(acc as Field, encoded);
    let mut slices: [u32; 7] = [0; 7];

    for i in 0..7 {
        slices[i] = (acc & 1023) as u32;
        acc >>= 10;
    }

    slices
}

pub(crate) fn decode_xor(encoded: Field) -> Field {
    //Safety: split input into 5-bit slices.
    //        Because the input is in base4, we actually obtain 10-bit slices
    //        We need to validate the correctness of these slice claims by asserting their sum equals `encoded`,
    //        and we also need to validate the bit range of each slice
    //        (we get an implicit range constraint for free by indexing our BASE4_XOR_DECODE_5BIT_TABLE lookup table)
    let slices = unsafe { __split_into_base4_5bit_slices(encoded) };

    // println(f"encoded slices {slices}");
    let mut reconstructed: Field = 0;
    let mut decoded: Field = 0;
    for i in 0..7 {
        reconstructed *= 1024;
        reconstructed += slices[6 - i] as Field;
        decoded *= 32;
        decoded += BASE4_XOR_DECODE_5BIT_TABLE[slices[6 - i]];
    }
    assert_eq(reconstructed, encoded);

    decoded
}

pub(crate) fn decode_round1(b: Field, c: Field, d: Field) -> Field {
    let encoded_a: Field = 0x55555555555555555 + b + c - d;
    let encoded_b = c + d;

    // Safety: split input into base4 5bit slices (i.e. 10 bit slices)
    //         we validate the sum of the slices equals the input.
    //         indexing `BASE4_MAJORITY_DECODE_5BIT_TABLE` by each slice is an implicit range check
    let slices_A = unsafe { __split_into_base4_5bit_slices(encoded_a) };
    let mut reconstructed_A: Field = 0;
    let mut decoded_A: Field = 0;
    for i in 0..7 {
        reconstructed_A *= 1024;
        reconstructed_A += slices_A[6 - i] as Field;
        decoded_A *= 32;
        decoded_A += BASE4_ROUND1_A_DECODE_5BIT_TABLE[slices_A[6 - i]];
    }
    assert_eq(reconstructed_A, encoded_a);

    // Safety: split input into base4 5bit slices
    let slices_B = unsafe { __split_into_base4_5bit_slices(encoded_b) };
    let mut reconstructed_B: Field = 0;
    let mut decoded_B: Field = 0;
    for i in 0..7 {
        reconstructed_B *= 1024;
        reconstructed_B += slices_B[6 - i] as Field;
        decoded_B *= 32;
        decoded_B += BASE4_ROUND1_B_DECODE_5BIT_TABLE[slices_B[6 - i]];
    }
    assert_eq(reconstructed_B, encoded_b);

    decoded_A + decoded_B
}

pub(crate) fn decode_round3(a: Field, b: Field, c: Field) -> Field {
    let encoded = a + b + c;
    // Safety: split input into base4 5bit slices (i.e. 10 bit slices)
    //         we validate the sum of the slices equals the input.
    //         indexing `BASE4_ROUND3_DECODE_5BIT_TABLE` by each slice is an implicit range check
    let slices = unsafe { __split_into_base4_5bit_slices(encoded) };
    let mut reconstructed: Field = 0;
    let mut decoded: Field = 0;
    for i in 0..7 {
        reconstructed *= 1024;
        reconstructed += slices[6 - i] as Field;
        decoded *= 32;
        decoded += BASE4_ROUND3_DECODE_5BIT_TABLE[slices[6 - i]];
    }
    assert_eq(reconstructed, encoded);

    decoded
}

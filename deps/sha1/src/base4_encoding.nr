use crate::tables::{BASE4_ENCODE_8BIT_TABLE, BASE4_POWERS};


pub(crate) struct Encoded {
    pub(crate) raw: Field,
    pub(crate) encoded: Field,
}

unconstrained fn decompose_into_8bit_chunks(input: Field) -> [u32; 4] {
    let mut r: [u32; 4] = [0; 4];

    let bytes = input.to_le_bytes::<4>();

    r[0] = bytes[0] as u32;
    r[1] = bytes[1] as u32;
    r[2] = bytes[2] as u32;
    r[3] = bytes[3] as u32;
    r
}

pub(crate) fn encode_base4(input: Field) -> Encoded {
    //Safety: split input into 8 bit slices, validate the sum equals the input
    let s = unsafe { decompose_into_8bit_chunks(input) };
    let mut reconstructed: Field = s[3] as Field;
    reconstructed *= 256;
    reconstructed += s[2] as Field;
    reconstructed *= 256;
    reconstructed += s[1] as Field;
    reconstructed *= 256;
    reconstructed += s[0] as Field;
    assert_eq(reconstructed, input);

    let mut base4_encoded_slices: [Field; 4] = [0; 4];
    // 18 gates?

    base4_encoded_slices[0] = BASE4_ENCODE_8BIT_TABLE[s[0]];
    base4_encoded_slices[1] = BASE4_ENCODE_8BIT_TABLE[s[1]];
    base4_encoded_slices[2] = BASE4_ENCODE_8BIT_TABLE[s[2]];
    base4_encoded_slices[3] = BASE4_ENCODE_8BIT_TABLE[s[3]];

    let mut result = base4_encoded_slices[3];
    result *= BASE4_POWERS[8];
    result += base4_encoded_slices[2] as Field;
    result *= BASE4_POWERS[8];
    result += base4_encoded_slices[1] as Field;
    result *= BASE4_POWERS[8];
    result += base4_encoded_slices[0] as Field;

    Encoded { raw: input, encoded: result }
}

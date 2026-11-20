use crate::base4_encoding::Encoded;

unconstrained fn __reduce_modulo_32(input: Field) -> (Field, Field) {
    let input32 = input as u64;

    let remainder = input32 & 0xffffffff;
    let modulus = input32 >> 32;

    (modulus as Field, remainder as Field)
}

pub(crate) fn reduce_modulo_32(input: Field) -> Field {
    // Safety: obtain result and then validate result is correct
    let (modulus, remainder) = unsafe { __reduce_modulo_32(input) };

    modulus.assert_max_bit_size::<8>();
    remainder.assert_max_bit_size::<32>();
    assert_eq(modulus * 0x100000000 + remainder, input);

    remainder
}

unconstrained fn leftrotate_30_base2_get_chunks(input: Field) -> (Field, Field) {
    let r = input as u32;

    let rlo = r & 0x3;
    let rhi = (r >> 2);
    (rlo as Field, rhi as Field)
}

unconstrained fn leftrotate_30_base4_get_chunks(input: Field) -> (Field, Field) {
    let r = input as u64;

    let rlo = r & 0xf;
    let rhi = (r >> 4);
    (rlo as Field, rhi as Field)
}

pub(crate) fn leftrotate_30(input: Encoded) -> Encoded {
    // Safety: split input into lo and hi chunks, then validate chunks are correct
    let (rawlo, rawhi) = unsafe { leftrotate_30_base2_get_chunks(input.raw) };
    rawlo.assert_max_bit_size::<2>();
    rawhi.assert_max_bit_size::<30>();
    assert_eq(rawlo + (rawhi * 4), input.raw);

    let rotate_base2 = rawhi + (rawlo * 0x40000000);

    // Safety: split input into lo and hi chunks, then validate chunks are correct
    let (encoded_lo, encoded_hi) = unsafe { leftrotate_30_base4_get_chunks(input.encoded) };
    encoded_lo.assert_max_bit_size::<4>();
    encoded_hi.assert_max_bit_size::<60>();
    assert_eq(encoded_lo + (encoded_hi * 16), input.encoded);

    let rotate_base4 = encoded_hi + (encoded_lo * 0x1000000000000000);

    Encoded { raw: rotate_base2, encoded: rotate_base4 }
}

unconstrained fn leftrotate_1_base2_get_chunks(input: Field) -> (Field, Field) {
    let r = input as u32;

    let rlo = r & 0x7fffffff;
    let rhi = (r >> 31);
    (rlo as Field, rhi as Field)
}

unconstrained fn leftrotate_1_base4_get_chunks(input: Field) -> (Field, Field) {
    let r = input as u64;

    let rlo = r & 0x3fffffffffffffff;
    let rhi = (r >> 62);
    (rlo as Field, rhi as Field)
}

pub(crate) fn leftrotate_1(input: Encoded) -> Encoded {
    // Safety: split input into lo and hi chunks, then validate chunks are correct
    let (rawlo, rawhi) = unsafe { leftrotate_1_base2_get_chunks(input.raw) };
    rawlo.assert_max_bit_size::<31>();
    rawhi.assert_max_bit_size::<1>();
    assert_eq(rawlo + (rawhi * 0x80000000), input.raw);

    let rotate_base2 = rawhi + (rawlo * 2);

    // Safety: split input into lo and hi chunks, then validate chunks are correct
    let (encoded_lo, encoded_hi) = unsafe { leftrotate_1_base4_get_chunks(input.encoded) };
    encoded_lo.assert_max_bit_size::<62>();
    encoded_hi.assert_max_bit_size::<2>();
    assert_eq(encoded_lo + (encoded_hi * 0x4000000000000000), input.encoded);

    let rotate_base4 = encoded_hi + (encoded_lo * 4);

    Encoded { raw: rotate_base2, encoded: rotate_base4 }
}

unconstrained fn leftrotate_5_base2_get_chunks(input: Field) -> (Field, Field) {
    let r = input as u32;
    let rlo = r & 0x7ffffff;
    let rhi = r >> 27;

    (rlo as Field, rhi as Field)
}
pub(crate) fn leftrotate_5(input: Field) -> Field {

    // Safety: split input into lo and hi chunks, then validate chunks are correct
    let (lo, hi) = unsafe { leftrotate_5_base2_get_chunks(input) };
    lo.assert_max_bit_size::<27>();
    hi.assert_max_bit_size::<5>();
    assert_eq(lo + (hi * 0x8000000), input);

    let result = lo * 0x20 + hi;
    result
}

// Convert 64-byte array to array of 16 u32s
pub(crate) fn msg_u8_to_u32(msg: [u8; 64]) -> [u32; 16] {
    let mut msg32: [u32; 16] = [0; 16];

    for i in 0..16 {
        let mut msg_field: Field = 0;
        for j in 0..4 {
            msg_field = msg_field * 256 + msg[64 - 4 * (i + 1) + j] as Field;
        }

        // TODO: fix expensive conversion
        msg32[15 - i] = msg_field as u32;
    }

    msg32
}

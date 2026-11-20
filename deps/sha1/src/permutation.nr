use crate::base4_decoding::{decode_round1, decode_round3, decode_xor};
use crate::base4_encoding::{encode_base4, Encoded};
use crate::bit_utils::{leftrotate_1, leftrotate_30, leftrotate_5, msg_u8_to_u32, reduce_modulo_32};
use std::ops::WrappingAdd;

// Size of the message block when packed as 8-byte integer array.
global INT_BLOCK_SIZE: u32 = 16;

type INT_BLOCK = [u32; INT_BLOCK_SIZE];

// The state accumulates the blocks.
// Its overall size is the same as the `HASH`.
type STATE = [u32; 5];

global SHA1_INITIAL_HASH_VALUES: [u32; 5] =
    [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

fn extend_witness(witness: [Field; 16]) -> [Field; 80] {
    let mut w: [Encoded; 80] = [Encoded { raw: 0, encoded: 0 }; 80];
    for i in 0..16 {
        w[i] = encode_base4(witness[i]);
    }

    // w[i] = (w[i-3] xor w[i-8] xor w[i-14] xor w[i-16]) leftrotate 1
    for i in 16..80 {
        let w0 = decode_xor(w[i - 3].encoded + w[i - 8].encoded + w[i - 14].encoded);
        let w0_encoded = encode_base4(w0);
        let w1 = decode_xor(w[i - 16].encoded + w0_encoded.encoded);

        let w_out = encode_base4(w1);
        w[i] = leftrotate_1(w_out);
    }

    let mut result: [Field; 80] = [0; 80];
    for i in 0..80 {
        result[i] = w[i].raw;
    }
    result
}

pub(crate) struct RoundState {
    a: Encoded,
    b: Encoded,
    c: Encoded,
    d: Encoded,
    e: Encoded,
}

// TODO: initialize this via a constant method that adds no constraints?
impl RoundState {
    fn new() -> Self {
        RoundState {
            a: encode_base4(SHA1_INITIAL_HASH_VALUES[0] as Field),
            b: encode_base4(SHA1_INITIAL_HASH_VALUES[0] as Field),
            c: encode_base4(SHA1_INITIAL_HASH_VALUES[1] as Field),
            d: encode_base4(SHA1_INITIAL_HASH_VALUES[2] as Field),
            e: encode_base4(SHA1_INITIAL_HASH_VALUES[3] as Field),
        }
    }
}

fn sha1_compression(_input: INT_BLOCK, _state: STATE) -> STATE {
    let mut message_input: [Field; 16] = [0; 16];
    for i in 0..16 {
        message_input[i] = _input[i] as Field;
    }

    let mut state: RoundState = RoundState {
        a: encode_base4(_state[0] as Field),
        b: encode_base4(_state[1] as Field),
        c: encode_base4(_state[2] as Field),
        d: encode_base4(_state[3] as Field),
        e: encode_base4(_state[4] as Field),
    };

    let mut w: [Field; 80] = extend_witness(message_input);

    compress(&mut state, w);

    let mut output: STATE = [0; 5];
    output[0] = state.a.raw as u32;
    output[1] = state.b.raw as u32;
    output[2] = state.c.raw as u32;
    output[3] = state.d.raw as u32;
    output[4] = state.e.raw as u32;
    output
}

fn compress(state: &mut RoundState, w: [Field; 80]) {
    let mut k: Field = 0;
    let mut f: Field = 0;
    for i in 0..80 {
        if (i <= 19) {
            // f = (b and c) or ((not b) and d)
            f = decode_round1(state.b.encoded, state.c.encoded, state.d.encoded);
            k = 0x5A827999;
        } else if (i <= 39) {
            // f = b ^ c ^ d
            f = decode_xor(state.b.encoded + state.c.encoded + state.d.encoded);
            k = 0x6ED9EBA1;
        } else if (i <= 59) {
            // f = (b & c) ^ (b & d) ^ (c & d)
            f = decode_round3(state.b.encoded, state.c.encoded, state.d.encoded);
            k = 0x8F1BBCDC;
        } else {
            // f = b ^ c ^ d
            f = decode_xor(state.b.encoded + state.c.encoded + state.d.encoded);
            k = 0xCA62C1D6;
        }

        let temp = reduce_modulo_32(leftrotate_5(state.a.raw) + f + state.e.raw + k + w[i]);
        state.e = state.d;
        state.d = state.c;
        state.c = leftrotate_30(state.b);
        state.b = state.a;
        state.a = encode_base4(temp);
    }
}

global SHA1_LENGTH_PARAMETER_BYTES: u32 = 8;
global SHA1_BLOCK_SIZE: u32 = 64;

// SHA-1 hash function
pub(crate) fn digest<let N: u32>(msg: [u8; N]) -> [u8; 20] {
    // noir-fmt:ignore
    let mut h: [u32; 5] = SHA1_INITIAL_HASH_VALUES;

    let mut c: [u32; 5] = [0; 5]; // Compression of current message block as sequence of u32
    let mut out_h: [u8; 20] = [0; 20]; // Digest as sequence of bytes

    let num_blocks = (N + SHA1_LENGTH_PARAMETER_BYTES + SHA1_BLOCK_SIZE) / SHA1_BLOCK_SIZE;

    let num_padded_bytes = num_blocks * SHA1_BLOCK_SIZE;
    let mut padded_msg: [u8; ((N + SHA1_LENGTH_PARAMETER_BYTES + SHA1_BLOCK_SIZE) / SHA1_BLOCK_SIZE) * SHA1_BLOCK_SIZE] = [
        0; ((N + SHA1_LENGTH_PARAMETER_BYTES + SHA1_BLOCK_SIZE) / SHA1_BLOCK_SIZE) * SHA1_BLOCK_SIZE
    ];

    for i in 0..N {
        padded_msg[i] = msg[i];
    }
    padded_msg[N] = 128;
    // N.B. assuming the message length (in bits) can be covered in 32 bits (approx 16MB message!)
    let length_byte_0: u8 = ((N * 8) as u8) & 255;
    let length_byte_1: u8 = ((N * 8) >> 8) as u8 & 255;
    let length_byte_2: u8 = ((N * 8) >> 16) as u8 & 255;
    let length_byte_3: u8 = ((N * 8) >> 24) as u8 & 255;
    padded_msg[num_padded_bytes - 1] = length_byte_0;
    padded_msg[num_padded_bytes - 2] = length_byte_1;
    padded_msg[num_padded_bytes - 3] = length_byte_2;
    padded_msg[num_padded_bytes - 4] = length_byte_3;

    let mut block_bytes: [u8; 64] = [0; 64];
    for i in 0..num_blocks {
        for j in 0..64 {
            block_bytes[j] = padded_msg[i * 64 + j];
        }
        c = sha1_compression(msg_u8_to_u32(block_bytes), h);
        for j in 0..5 {
            h[j] = h[j].wrapping_add(c[j]);
        }
    }

    // Return final hash as byte array
    for j in 0..5 {
        let h_bytes: [u8; 4] = (h[4 - j] as Field).to_le_bytes();
        for k in 0..4 {
            out_h[19 - 4 * j - k] = h_bytes[k];
        }
    }
    out_h
}

pub(crate) fn digest_var<let N: u32>(msg: BoundedVec<u8, N>) -> [u8; 20] {
    // noir-fmt:ignore
    let mut h: [u32; 5] =SHA1_INITIAL_HASH_VALUES;

    let mut c: [u32; 5] = [0; 5]; // Compression of current message block as sequence of u32
    let mut out_h: [u8; 20] = [0; 20]; // Digest as sequence of bytes

    let num_blocks = (N + SHA1_LENGTH_PARAMETER_BYTES + SHA1_BLOCK_SIZE) / SHA1_BLOCK_SIZE;

    let mut padded_msg: [u8; ((N + SHA1_LENGTH_PARAMETER_BYTES + SHA1_BLOCK_SIZE) / SHA1_BLOCK_SIZE) * SHA1_BLOCK_SIZE] = [
        0; ((N + SHA1_LENGTH_PARAMETER_BYTES + SHA1_BLOCK_SIZE) / SHA1_BLOCK_SIZE) * SHA1_BLOCK_SIZE
    ];

    let msg_text = msg.storage();
    for i in 0..N {
        padded_msg[i] = msg_text[i];
    }

    let msg_length = msg.len();

    let num_used_blocks =
        (msg_length + SHA1_LENGTH_PARAMETER_BYTES + SHA1_BLOCK_SIZE) / SHA1_BLOCK_SIZE;

    let num_used_padded_bytes = num_used_blocks * SHA1_BLOCK_SIZE;
    // N.B. this line turns `padded_msg` into a RAM array, which is expensive!
    // A cheaper version of this would pack the inputs into 16-byte words && only modify 1 word,
    // before unpacking into a byte array
    padded_msg[msg_length] = 128;
    // N.B. assuming the message length (in bits) can be covered in 32 bits (approx 16MB message!)
    let length_bytes = (msg_length as Field * 8).to_le_bytes::<4>();
    padded_msg[num_used_padded_bytes - 1] = length_bytes[0];
    padded_msg[num_used_padded_bytes - 2] = length_bytes[1];
    padded_msg[num_used_padded_bytes - 3] = length_bytes[2];
    padded_msg[num_used_padded_bytes - 4] = length_bytes[3];

    let mut output_h: [u32; 5] = h;
    let mut block_bytes: [u8; 64] = [0; 64];
    for i in 0..num_blocks {
        for j in 0..64 {
            block_bytes[j] = padded_msg[i * 64 + j];
        }
        c = sha1_compression(msg_u8_to_u32(block_bytes), h);
        for j in 0..5 {
            h[j] = h[j].wrapping_add(c[j]);
        }
        if (i < num_used_blocks) {
            output_h = h;
        }
    }

    // Return final hash as byte array
    for j in 0..5 {
        let h_bytes: [u8; 4] = (output_h[4 - j] as Field).to_le_bytes();
        for k in 0..4 {
            out_h[19 - 4 * j - k] = h_bytes[k];
        }
    }
    out_h
}

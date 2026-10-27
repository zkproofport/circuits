// Reading claims out of a JWT payload, once.
//
// noir-jwt's `get_claim_*` decode the whole payload again on every call. This
// circuit reads seven claims, so it decodes once here and looks every claim up
// in that one haystack.
//
// Two rules the library does not enforce and this module does:
//
// 1. The decode starts at the payload start. `base64_decode_offset` is a
//    private input; nothing in noir-jwt ties it to where the payload begins.
//    Decoding base64 from a position that is not a multiple of four from the
//    payload start produces different bytes -- the original bit stream
//    shifted by 2, 4 or 6 bits -- and those bytes can be steered by any
//    attacker-chosen claim value (a display name) into something like
//    `"email":"...",`. Requiring the byte just before the offset to be the
//    `.` between header and payload pins the decode to the real payload: `.`
//    is not in the base64url alphabet, so `header.payload` holds exactly one.
//    The builders must therefore keep that `.` inside `partial_data`.
//
// 2. A key match is a key. The first `"key"` in the payload is used (the same
//    occurrence string_search's hint picks); the byte before it must be `{`
//    or `,` and the byte after it `:`. So a key spelled inside another key
//    (`"a\"nonce":`) or an array element `"nonce"` refuses the proof rather
//    than being read. String values may not contain a backslash, so an
//    escaped quote cannot end one early. Inside a JSON string every `"` is
//    escaped, so `"key":` cannot occur inside a claim value at all.
//
// What this does NOT rule out: a payload that carries the same key twice. The
// position of a match is a prover hint, and the circuit does not prove the
// absence of a second one. Neither provider documents or is known to emit
// duplicate claims, and only a token signed by one passes the signature check.

use base64::BASE64_URL_DECODER;
use string_search::{StringBody, SubString};

global QUOTE: u8 = 34;
global COLON: u8 = 58;
global COMMA: u8 = 44;
global OPEN_BRACE: u8 = 123;
global CLOSE_BRACE: u8 = 125;
global BACKSLASH: u8 = 92;
global PERIOD: u8 = 46;

// Ten digits cover unix seconds until the year 2286; 19 is the most a u64 can
// hold without overflowing.
global MAX_NUMBER_DIGITS: u32 = 19;

pub fn decode_payload<let N: u32>(
    data: BoundedVec<u8, N>,
    base64_decode_offset: u32,
) -> StringBody<((((N / 4) * 3) + 31) / 31) * 31, (((N / 4) * 3) + 31) / 31, ((N / 4) * 3)> {
    assert(
        (base64_decode_offset > 0) & (base64_decode_offset < data.len()),
        "base64_decode_offset is outside partial_data",
    );
    assert(
        data.storage()[base64_decode_offset - 1] == PERIOD,
        "base64_decode_offset is not the payload start",
    );

    // The builders cut the SHA precompute at the block holding the `.`, so the
    // payload starts within the first 64 bytes. That bound lets the shift be a
    // plain indexed read rather than noir-jwt's per-byte modulo rotation.
    assert(base64_decode_offset <= 64, "payload start is not in the first block of partial_data");
    let mut extended: [u8; N + 64] = [0; N + 64];
    for i in 0..N {
        extended[i] = data.storage()[i];
    }
    let mut rotated: [u8; N] = [0; N];
    for i in 0..N {
        rotated[i] = extended[i + base64_decode_offset];
    }
    let to_decode: BoundedVec<u8, N> =
        BoundedVec::from_parts(rotated, data.len() - base64_decode_offset);
    let payload: BoundedVec<u8, ((N / 4) * 3)> = BASE64_URL_DECODER::decode_var(to_decode);

    StringBody::new(payload.storage(), payload.len())
}

/// The raw value of `key`. Quoted values are returned without their quotes.
pub fn claim_value<let P: u32, let C: u32, let B: u32, let K: u32, let V: u32>(
    haystack: StringBody<P, C, B>,
    key: [u8; K],
    is_value_quoted: bool,
) -> BoundedVec<u8, V> {
    // Safety: every byte returned is compared with the haystack below.
    let value: BoundedVec<u8, V> =
        unsafe { extract_value_unconstrained::<P, C, B, K, V>(haystack, key, is_value_quoted) };

    let mut quoted_key: [u8; K + 2] = [0; K + 2];
    quoted_key[0] = QUOTE;
    for i in 0..K {
        quoted_key[i + 1] = key[i];
    }
    quoted_key[K + 1] = QUOTE;
    let needle: SubString<(((K + 2) + 31) / 31) * 31, (K + 2) / 31, K + 2> =
        SubString::new(quoted_key, K + 2);

    let (_, position): (bool, u32) = haystack.substring_match(needle);

    assert(position > 0, "claim key is not inside the payload object");
    let before = haystack.body[position - 1];
    assert((before == OPEN_BRACE) | (before == COMMA), "claim key is not a top-level key");

    let colon_index = position + K + 2;
    assert(haystack.body[colon_index] == COLON, "claim key is not followed by a colon");

    let mut value_start = colon_index + 1;
    let mut after_value = value_start + value.len();
    if is_value_quoted {
        value_start = value_start + 1;
        after_value = after_value + 2;
        assert(haystack.body[value_start - 1] == QUOTE, "claim value has no opening quote");
        assert(haystack.body[after_value - 1] == QUOTE, "claim value has no closing quote");
    }

    for i in 0..V {
        if i < value.len() {
            assert(haystack.body[value_start + i] == value.storage()[i], "claim value mismatch");
            if is_value_quoted {
                assert(value.storage()[i] != BACKSLASH, "claim value contains an escape");
            }
        }
    }

    let terminator = haystack.body[after_value];
    assert((terminator == COMMA) | (terminator == CLOSE_BRACE), "claim value is not terminated");

    value
}

pub fn string_claim<let P: u32, let C: u32, let B: u32, let K: u32, let V: u32>(
    haystack: StringBody<P, C, B>,
    key: [u8; K],
) -> BoundedVec<u8, V> {
    claim_value::<P, C, B, K, V>(haystack, key, true)
}

pub fn number_claim<let P: u32, let C: u32, let B: u32, let K: u32>(
    haystack: StringBody<P, C, B>,
    key: [u8; K],
) -> u64 {
    let digits: BoundedVec<u8, MAX_NUMBER_DIGITS> =
        claim_value::<P, C, B, K, MAX_NUMBER_DIGITS>(haystack, key, false);
    assert(digits.len() > 0, "number claim is empty");
    let mut n: Field = 0;
    for i in 0..MAX_NUMBER_DIGITS {
        if i < digits.len() {
            let d = digits.storage()[i];
            assert((d >= 48) & (d <= 57), "number claim is not a decimal integer");
            n = n * 10 + (d - 48) as Field;
        }
    }
    // 19 digits stay below 2^64, so the cast cannot wrap.
    n as u64
}

pub fn bool_claim<let P: u32, let C: u32, let B: u32, let K: u32>(
    haystack: StringBody<P, C, B>,
    key: [u8; K],
) -> bool {
    let v: BoundedVec<u8, 5> = claim_value::<P, C, B, K, 5>(haystack, key, false);
    let is_true = equals(v, "true".as_bytes());
    let is_false = equals(v, "false".as_bytes());
    assert(is_true | is_false, "boolean claim is neither true nor false");
    is_true
}

/// `v` holds exactly `s`. Bytes past `v.len()` are ignored, as they must be:
/// nothing constrains them.
pub fn equals<let V: u32, let L: u32>(v: BoundedVec<u8, V>, s: [u8; L]) -> bool {
    let mut same = v.len() == L;
    for i in 0..L {
        if i < V {
            same = same & (v.storage()[i] == s[i]);
        }
    }
    same
}

unconstrained fn extract_value_unconstrained<let P: u32, let C: u32, let B: u32, let K: u32, let V: u32>(
    haystack: StringBody<P, C, B>,
    key: [u8; K],
    is_value_quoted: bool,
) -> BoundedVec<u8, V> {
    // The first `"key"` anywhere, the same occurrence string_search's own hint
    // picks, so the constrained match and this extraction agree. If that first
    // occurrence is not a real key, the constrained checks refuse the proof.
    let mut position: u32 = 0;
    let mut found = false;
    for i in 0..B {
        if !found {
            if i + K + 2 <= haystack.byte_length {
                if (haystack.body[i] == QUOTE) & (haystack.body[i + K + 1] == QUOTE) {
                    let mut same = true;
                    for j in 0..K {
                        same = same & (haystack.body[i + 1 + j] == key[j]);
                    }
                    if same {
                        position = i;
                        found = true;
                    }
                }
            }
        }
    }
    assert(found, "claim key not found in the payload");

    let mut start = position + K + 3;
    if is_value_quoted {
        start += 1;
    }
    let mut value: BoundedVec<u8, V> = BoundedVec::new();
    let mut done = false;
    for i in 0..V {
        if !done & (start + i < P) {
            let c = haystack.body[start + i];
            if (c == QUOTE) | (c == COMMA) | (c == CLOSE_BRACE) {
                done = true;
            } else {
                value.push(c);
            }
        }
    }
    value
}

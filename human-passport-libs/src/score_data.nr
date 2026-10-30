// The `data` field of a Human Passport scoreV2 attestation, read the way
// Solidity reads it.
//
// The schema, from GitcoinResolver._setScoreV2 (passportxyz/eas-proxy):
//
//   abi.decode(data, (bool, uint8, uint128, uint32, uint32, Stamp[]))
//                     passing  decimals  scorer_id  score  threshold  stamps
//
// Every static field is one 32-byte word in the head, so the five values this
// circuit needs sit at fixed offsets and do not depend on how many stamps
// follow. The stamps are not parsed: they matter only because the issuer's
// signature covers keccak256(data), which `request.nr` computes over the whole
// thing.
//
// WHY THE HIGH BYTES ARE CHECKED. abi.decode reverts on a word whose unused
// high bytes are not zero, so data with dirty padding never became an
// attestation on chain. Reading only the low bytes here would accept bytes
// Solidity refuses -- the circuit would then disagree with the contract about
// what the score is. The issuer signs the data, so a prover cannot invent such
// bytes; the check keeps the two readings identical anyway, and costs nothing
// next to the keccak.

pub global HEAD_BYTES: u32 = 192;

/// Offset of the stamps array, relative to the start of `data`: six head words.
global STAMPS_OFFSET: u8 = 0xc0;

/// Passport writes four decimals (score 25.1234 is 251234). The resolver
/// rescales other values; this circuit does not -- a different number would
/// change what `min_score` means, so it is refused rather than guessed.
pub global SCORE_DECIMALS: u8 = 4;

pub struct ScoreHead {
    pub passing: bool,
    pub scorer_id: Field,
    pub score: u32,
    pub threshold: u32,
}

/// Big-endian value of the low `width` bytes of head word `word`, and whether
/// the word's other bytes are all zero. The caller asserts the second with a
/// message naming the field.
fn word_tail<let N: u32>(data: [u8; N], word: u32, width: u32) -> (Field, bool) {
    let start = word * 32;
    let mut acc: Field = 0;
    let mut high: u32 = 0;
    for i in 0..32 {
        let b = data[start + i];
        if i < 32 - width {
            high += b as u32;
        } else {
            acc = acc * 256 + b as Field;
        }
    }
    (acc, high == 0)
}

pub fn parse_score_head<let N: u32>(data: [u8; N], data_len: u32) -> ScoreHead {
    assert(data_len >= HEAD_BYTES, "score data shorter than its head");
    assert(data_len <= N, "score data longer than the circuit allows");

    let (passing, clean) = word_tail(data, 0, 1);
    assert(clean, "score data: passing has non-zero padding");
    assert((passing == 0) | (passing == 1), "score data: passing is not a bool");

    let (decimals, clean) = word_tail(data, 1, 1);
    assert(clean, "score data: decimals has non-zero padding");
    assert(decimals == SCORE_DECIMALS as Field, "score data: decimals is not 4");

    let (scorer_id, clean) = word_tail(data, 2, 16);
    assert(clean, "score data: scorer_id has non-zero padding");

    let (score, clean) = word_tail(data, 3, 4);
    assert(clean, "score data: score has non-zero padding");

    let (threshold, clean) = word_tail(data, 4, 4);
    assert(clean, "score data: threshold has non-zero padding");

    // Standard ABI encoding puts the only dynamic member right after the head.
    // Anything else is not what the resolver decodes.
    let (stamps_offset, clean) = word_tail(data, 5, 1);
    assert(clean, "score data: stamps offset has non-zero padding");
    assert(stamps_offset == STAMPS_OFFSET as Field, "score data: stamps offset is not 0xc0");

    ScoreHead {
        passing: passing == 1,
        scorer_id,
        score: score as u32,
        threshold: threshold as u32,
    }
}

// ---------------------------------------------------------------------------

#[test]
fn reads_each_head_field() {
    let mut d: [u8; 256] = [0; 256];
    d[31] = 1; // passing
    d[63] = 4; // decimals
    d[94] = 0x01;
    d[95] = 0x4f; // scorer 335
    d[124] = 0x00;
    d[125] = 0x03;
    d[126] = 0xd5;
    d[127] = 0x12; // score 251154
    d[158] = 0x4e;
    d[159] = 0x20; // threshold 20000
    d[191] = 0xc0;
    let h = parse_score_head(d, 224);
    assert(h.passing);
    assert(h.scorer_id == 335);
    assert(h.score == 251154);
    assert(h.threshold == 20000);
}

#[test(should_fail_with = "score data: decimals is not 4")]
fn other_decimals_are_refused() {
    let mut d: [u8; 256] = [0; 256];
    d[63] = 2;
    d[191] = 0xc0;
    let _ = parse_score_head(d, 224);
}

#[test(should_fail_with = "score data: score has non-zero padding")]
fn dirty_score_padding_is_refused() {
    let mut d: [u8; 256] = [0; 256];
    d[63] = 4;
    d[100] = 1; // inside the score word, above its four bytes
    d[191] = 0xc0;
    let _ = parse_score_head(d, 224);
}

#[test(should_fail_with = "score data shorter than its head")]
fn a_short_head_is_refused() {
    let d: [u8; 256] = [0; 256];
    let _ = parse_score_head(d, 191);
}

#[test(should_fail_with = "score data: passing is not a bool")]
fn a_non_bool_passing_word_is_refused() {
    let mut d: [u8; 256] = [0; 256];
    d[31] = 2;
    d[63] = 4;
    d[191] = 0xc0;
    let _ = parse_score_head(d, 224);
}

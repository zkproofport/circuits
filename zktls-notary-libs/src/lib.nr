// Schema-driven claim over a TLSNotary-committed prefix of a JSON response body.
//
// The transport layer (MPC-TLS or proxy mode) authenticates the server response
// and hands the verifier a SHA-256 commitment to a prefix of the HTTP response
// body, starting at its first byte:
//   commitment = SHA256(body[0..P] || blinder), blinder = 16 bytes
// where P is either the whole body, or exactly the tier size N when the body is
// longer than N. The rest of the body is neither revealed nor committed.
// This circuit proves, without revealing the prefix:
//   1. the private prefix opens that commitment;
//   2. each of up to A assertions reads the member at its JSON path, checked
//      against the JSON structure, not a byte pattern. A path is up to SEG_MAX
//      segments, each an object key or `[]` ("some element of this array"), e.g.
//      `kakao_account.age_range`, `[].login`, `data.items[].owner.login`. Within a
//      prefix tier, `[]` means some element inside the committed prefix;
//   3. every assertion's value satisfies its operator against its operand (ANDed);
//   4. the nullifier is derived from a top-level member (the account id) and the
//      scope, or, for claims without an account member (NF_NONE), from the scope;
//   5. claim_hash commits to the tier, every assertion (path, value kind,
//      operator, operand), the nullifier member and the scope. All of those are
//      private inputs: a relying party recomputes claim_hash from its proof request
//      and compares it with the public input;
//   6. request_hash and the proof date are public inputs, carried unchanged, so a
//      proof is bound to the request it answers (the relying party checks them).
//
// Path binding. The scan records, before every byte, whether it is inside a
// string and the position of the bracket opening the innermost container. The
// prover names, for every segment, the token (a key's opening quote, or an
// element's first byte) and the start of that segment's value. The circuit
// checks that each token's innermost container is the previous segment's value
// (the root bracket at byte 0 for the first), that a key is a real key token
// (outside strings, its exact name, then a colon), that a `[]` segment's value is
// a direct element of an array and that a key follows only an object. A fake key
// inside a string, a key at the wrong depth or in a sibling object, and an
// element of another array therefore all fail.
//
// Every member a claim reads, including the byte that closes its value, must sit
// inside the prefix. The JSON state at a byte depends only on the bytes before it.
//
// JSON whitespace (space, tab, CR, LF) may appear between tokens: between a key
// and its colon and between the colon and the value at most SEP_MAX bytes in
// total. Values are either strings without escapes, or bare literals (numbers,
// true, false, null). The root is an object or array; JSON whitespace may surround
// it, nothing else.

pub mod vectors;
pub mod vectors_ws;
pub mod vectors_deep;
pub mod testkit;
mod tests;
mod tests_ws;
mod tests_deep;
mod tests_guards;
mod tests_capacity;

use keccak256::keccak256;
use sha256::sha256_var;

pub global BLINDER_LEN: u32 = 16;
pub global KEY_MAX: u32 = 32;
pub global VAL_MAX: u32 = 32;
pub global SCOPE_LEN: u32 = 32;
// Bytes between a key's closing quote and its value (colon plus whitespace).
pub global SEP_MAX: u32 = 8;
// Path segments per assertion. Real API responses nest shallowly (Kakao 2,
// GitHub 1-3, Google 1); 8 covers REST and GraphQL envelopes such as
// `data.viewer.organizations.nodes[].login` with room to spare, and each segment
// costs a fixed ~KEY_MAX reads, so the tier's scan stays the dominant cost.
pub global SEG_MAX: u32 = 8;
// Assertions per claim, ANDed: the most any circuit takes, and the number of
// assertion slots the claim_hash encoding always has. A circuit's own capacity A
// (verify_claim's second generic, 1 to A_MAX) only sets how many assertions it
// can check; slots A..A_MAX of the encoding are zero, so one claim has one
// claim_hash whichever capacity proves it.
pub global A_MAX: u32 = 3;
// Zero bytes after the prefix in the copy the member checks read, so a read a few
// bytes past a token never needs its own bounds test: every token is first checked
// to lie inside the prefix, and no check reads further than PAD bytes beyond one.
pub global PAD: u32 = 80;

pub global SEG_NONE: u32 = 0;
pub global SEG_KEY: u32 = 1;
pub global SEG_ANY: u32 = 2;

pub global OP_EQ: u32 = 0;
pub global OP_NEQ: u32 = 1;
pub global OP_GT: u32 = 2;
pub global OP_LT: u32 = 3;
pub global OP_GTE: u32 = 4;
pub global OP_LTE: u32 = 5;
pub global OP_AGE_GTE: u32 = 6;
pub global OP_RANGE_MIN_GTE: u32 = 7;
pub global OP_ENDS_WITH: u32 = 8;
pub global OP_DATE_BEFORE: u32 = 9;
pub global OP_CONTAINS: u32 = 10;
pub global OP_IN: u32 = 11;
pub global OP_LAST: u32 = 11;

pub global KIND_STRING: u32 = 0;
pub global KIND_LITERAL: u32 = 1;
// Nullifier kind only: the claim reads no account member.
pub global NF_NONE: u32 = 2;

global QUOTE: u8 = 34;
global BACKSLASH: u8 = 92;
global COLON: u8 = 58;
global COMMA: u8 = 44;
global LBRACE: u8 = 123;
global RBRACE: u8 = 125;
global LBRACKET: u8 = 91;
global RBRACKET: u8 = 93;
global DASH: u8 = 45;
global TILDE: u8 = 126;

// claim_hash = SHA-256 of, version 4:
//   version | tier (2, big-endian) | n_asserts
//   | A_MAX x ( n_segs | SEG_MAX x (seg_kind | seg_len | seg_key[32])
//               | value_kind | op | operand_len | operand[32] )
//   | nf_key_len | nf_key[32] | nf_kind | scope[32]
// Unused assertions and segments are all zero.
pub global CLAIM_VERSION: u8 = 4;
pub global SEG_ENC: u32 = 34;
pub global ASSERT_ENC: u32 = 308; // 1 + SEG_MAX * SEG_ENC + 3 + VAL_MAX
pub global CLAIM_LEN: u32 = 994; // 4 + A_MAX * ASSERT_ENC + 34 + SCOPE_LEN
// nf_len | nf_value | scope
pub global NF_LEN: u32 = 65; // 1 + 32 + 32

pub struct JsonState<let N: u32> {
    // State BEFORE each byte.
    pub(crate) in_str: [bool; N],
    // Position of the bracket that opened the innermost enclosing container, or
    // N outside every container.
    pub(crate) cont: [u32; N],
}

/// A JSON path: `n` segments, each SEG_KEY (an object key) or SEG_ANY (`[]`).
pub struct Path {
    pub n: u32,
    pub kinds: [u32; SEG_MAX],
    pub keys: [[u8; KEY_MAX]; SEG_MAX],
    pub lens: [u32; SEG_MAX],
}

/// One assertion: the value at `path` is a `value_kind` value satisfying `op`.
pub struct Assert {
    pub path: Path,
    pub value_kind: u32,
    pub op: u32,
    pub operand: [u8; VAL_MAX],
    pub operand_len: u32,
}

/// Where the prover says each token of one path sits. Private.
///   tok[s]  the key's opening quote (SEG_KEY) or the element's first byte (SEG_ANY);
///   open[s] the first byte of that segment's value token (equal to tok for SEG_ANY);
///   value_offset, value_len: the final value's bytes (after the quote for a string).
pub struct Hint {
    pub tok: [u32; SEG_MAX],
    pub open: [u32; SEG_MAX],
    pub value_offset: u32,
    pub value_len: u32,
}

/// The whole claim. `N` is the tier: the largest prefix this instance accepts.
/// `A` is the capacity: the most assertions this instance checks (1 to A_MAX).
/// `whole` is public and set by the verifier: true when the committed range is
/// the entire body (then prefix_len <= N), false when it is the first N bytes
/// of a longer body (then prefix_len == N).
pub fn verify_claim<let N: u32, let A: u32>(
    // Private
    prefix: [u8; N],
    prefix_len: u32,
    blinder: [u8; BLINDER_LEN],
    root: u32,
    cont: [u32; N],
    n_asserts: u32,
    asserts: [Assert; A],
    hints: [Hint; A],
    nf_key: [u8; KEY_MAX],
    nf_key_len: u32,
    nf_kind: u32,
    nf_hint: Hint,
    scope: [u8; SCOPE_LEN],
    // Public
    commitment: [u8; 32],
    whole: bool,
    claim_hash: [u8; 32],
    proof_year: u32,
    proof_month: u32,
    proof_day: u32,
    nullifier: [u8; 32],
) {
    assert(N < 65536, "tier does not fit the claim encoding");
    std::static_assert((A >= 1) & (A <= A_MAX), "capacity must be 1 to A_MAX");
    assert(prefix_len <= N, "prefix longer than the tier");
    assert(prefix_len > 1, "empty body");
    if !whole {
        assert(prefix_len == N, "a partial prefix must be exactly the tier size");
    }

    // 1. Commitment opening: SHA256(prefix[..prefix_len] || blinder).
    let mut buf: [u8; N + BLINDER_LEN] = [0; N + BLINDER_LEN];
    for i in 0..N {
        buf[i] = prefix[i];
    }
    for j in 0..BLINDER_LEN {
        buf[prefix_len + j] = blinder[j];
    }
    let computed = sha256_var(buf, prefix_len + BLINDER_LEN);
    assert(computed == commitment, "prefix does not open the commitment");

    // 2 + 3. Every assertion: bind its path, check its predicate.
    let st = scan_structure(prefix, prefix_len, whole, cont, root);
    let mut pb: [u8; N + PAD] = [0; N + PAD];
    for i in 0..N {
        pb[i] = prefix[i];
    }
    // A claim with more assertions than this circuit holds is refused here, not
    // truncated: the remaining assertions would go unchecked.
    assert((n_asserts >= 1) & (n_asserts <= A), "bad assertion count");
    assert((proof_month >= 1) & (proof_month <= 12), "bad proof month");
    assert((proof_day >= 1) & (proof_day <= 31), "bad proof day");
    for a in 0..A {
        let x = asserts[a];
        if a < n_asserts {
            let value = bind_path(pb, prefix_len, st, root, x.path, hints[a], x.value_kind);
            let ok = apply_operator(
                x.op,
                value,
                hints[a].value_len,
                x.operand,
                x.operand_len,
                proof_year,
                proof_month,
                proof_day,
            );
            assert(ok, "predicate does not hold");
        } else {
            assert_unused(x);
        }
    }

    // 4. Nullifier.
    let mut nf_value: [u8; VAL_MAX] = [0; VAL_MAX];
    let mut nf_len: u32 = 0;
    if nf_kind == NF_NONE {
        assert(nf_key_len == 0, "NF_NONE takes no nullifier key");
        for j in 0..KEY_MAX {
            assert(nf_key[j] == 0, "nullifier key padding not zero");
        }
    } else {
        // The account member is always a member of the top-level object.
        nf_value = bind_path_upto::<1, _, _>(pb, prefix_len, st, root, top_path(nf_key, nf_key_len), nf_hint, nf_kind);
        nf_len = nf_hint.value_len;
    }
    assert(compute_nullifier(nf_value, nf_len, scope) == nullifier, "nullifier mismatch");

    // 5. Claim binding.
    assert(
        compute_claim_hash(N, n_asserts, asserts, nf_key, nf_key_len, nf_kind, scope) == claim_hash,
        "claim hash mismatch",
    );
}

/// The structure checks alone: the scan, and the root value's opening bracket, which
/// lies outside every container (so, by the scan, it is the first non-whitespace byte
/// and the only bracket at depth 0). Used by verify_claim and by the conformance probe.
pub fn scan_structure<let N: u32>(
    body: [u8; N],
    body_len: u32,
    whole: bool,
    cont: [u32; N],
    root: u32,
) -> JsonState<N> {
    let st = scan_json(body, body_len, whole, cont);
    assert(root < body_len, "root past prefix");
    let rb = at(body, root);
    assert((rb == LBRACE) | (rb == LBRACKET), "root is not an object or array");
    // Outside every container is also outside every string: the scan allows nothing but
    // whitespace and the root's bracket at depth 0.
    assert(cont_at(st, root) == N, "root is inside a container");
    st
}

pub fn top_path(key: [u8; KEY_MAX], len: u32) -> Path {
    let mut p = Path { n: 1, kinds: [SEG_NONE; SEG_MAX], keys: [[0; KEY_MAX]; SEG_MAX], lens: [0; SEG_MAX] };
    p.kinds[0] = SEG_KEY;
    p.keys[0] = key;
    p.lens[0] = len;
    p
}

fn assert_unused(x: Assert) {
    assert(x.path.n == 0, "unused assertion has a path");
    for s in 0..SEG_MAX {
        assert((x.path.kinds[s] == SEG_NONE) & (x.path.lens[s] == 0), "unused assertion has a segment");
        for j in 0..KEY_MAX {
            assert(x.path.keys[s][j] == 0, "unused assertion has a key");
        }
    }
    assert((x.value_kind == 0) & (x.op == 0) & (x.operand_len == 0), "unused assertion has a predicate");
    for j in 0..VAL_MAX {
        assert(x.operand[j] == 0, "unused assertion has an operand");
    }
}

fn is_ws(c: u8) -> bool {
    (c == 32) | (c == 9) | (c == 10) | (c == 13)
}

// in_str before every byte, and the innermost container `cont`, which the prover
// supplies and the scan checks byte by byte: before byte 0 it is N (outside every
// container); an opening bracket makes the next byte's container that bracket; a
// closing bracket makes it the container the closed bracket sat in, which is
// cont[that bracket]. Every cont[i] must equal that running value, so the prover
// has no freedom in it. (A read of the prover's array replaces a stack of open
// brackets, which costs far more per byte in a circuit, and has no depth limit.)
//
// JSON whitespace may come before the root value and after it, nothing else: at
// depth 0 the only other byte allowed is the root's opening bracket, once. A
// byte-order mark is not JSON whitespace and is refused. When the prefix is the
// whole body the root must have opened and closed, outside any string.
pub(crate) fn scan_json<let N: u32>(
    body: [u8; N],
    body_len: u32,
    whole: bool,
    cont: [u32; N],
) -> JsonState<N> {
    let mut st = JsonState { in_str: [false; N], cont };
    let mut in_str = false;
    let mut escaped = false;
    let mut cur: u32 = N;
    let mut root_seen = false;
    for i in 0..N {
        st.in_str[i] = in_str;
        assert(cont[i] == cur, "container hint mismatch");
        if i < body_len {
            let c = body[i];
            if in_str {
                if escaped {
                    escaped = false;
                } else if c == BACKSLASH {
                    escaped = true;
                } else if c == QUOTE {
                    in_str = false;
                }
            } else if cur == N {
                if (c == LBRACE) | (c == LBRACKET) {
                    assert(!root_seen, "bytes after the root value");
                    root_seen = true;
                    cur = i;
                } else {
                    assert(is_ws(c), "non-whitespace outside the root value");
                }
            } else if c == QUOTE {
                in_str = true;
            } else if (c == LBRACE) | (c == LBRACKET) {
                cur = i;
            } else if (c == RBRACE) | (c == RBRACKET) {
                // The bracket closes the kind it opened: `{` with `}`, `[` with `]`.
                assert((c == RBRACE) == (body[cur] == LBRACE), "closing bracket does not match");
                cur = cont[cur];
            }
        }
    }
    if whole {
        assert(root_seen, "no root value");
        assert(!in_str, "unterminated JSON string");
        assert(cur == N, "unbalanced JSON");
    }
    st
}

fn at<let N: u32>(body: [u8; N], idx: u32) -> u8 {
    let safe = if idx < N { idx } else { 0 };
    body[safe]
}

fn cont_at<let N: u32>(st: JsonState<N>, idx: u32) -> u32 {
    let safe = if idx < N { idx } else { 0 };
    st.cont[safe]
}

fn in_str_at<let N: u32>(st: JsonState<N>, idx: u32) -> bool {
    let safe = if idx < N { idx } else { 0 };
    st.in_str[safe]
}

// `"<name>"` starting at k, outside any string. k lies inside the prefix (checked by
// the caller), so k + 1 + KEY_MAX stays inside the padded copy.
fn check_key_token<let M: u32, let N: u32>(
    pb: [u8; M],
    st: JsonState<N>,
    k: u32,
    name: [u8; KEY_MAX],
    len: u32,
) {
    assert((len >= 1) & (len <= KEY_MAX), "bad key length");
    assert(pb[k] == QUOTE, "key does not start with a quote");
    assert(!in_str_at(st, k), "key quote is inside a string");
    for j in 0..KEY_MAX {
        if j < len {
            let c = name[j];
            assert((c != QUOTE) & (c != BACKSLASH), "key contains a quote or backslash");
            assert(pb[k + 1 + j] == c, "key name mismatch");
        } else {
            assert(name[j] == 0, "key padding not zero");
        }
    }
    assert(pb[k + 1 + len] == QUOTE, "key not closed");
}

// The bytes in [from, to) are JSON whitespace around exactly one colon. In valid
// JSON a string followed by a colon is a member key, and the value starts at `to`.
fn check_sep<let M: u32>(pb: [u8; M], from: u32, to: u32) {
    assert(to > from, "no colon after key");
    assert(to - from <= SEP_MAX, "too much whitespace after key");
    let mut colons: u32 = 0;
    for i in 0..SEP_MAX {
        if i < to - from {
            let c = pb[from + i];
            if c == COLON {
                colons += 1;
            } else {
                assert(is_ws(c), "no colon after key");
            }
        }
    }
    assert(colons == 1, "no colon after key");
}

// The first non-whitespace byte before `e` is `[` or `,`: e starts an array
// element (needed for a bare literal; brackets and strings directly inside an
// array are elements by the JSON grammar).
fn check_elem_delim<let N: u32>(body: [u8; N], e: u32) {
    assert(e >= 1, "element at byte 0");
    let mut found = false;
    let mut ok = false;
    for i in 1..SEP_MAX + 2 {
        if (!found) & (i <= e) {
            let c = at(body, e - i);
            if !is_ws(c) {
                found = true;
                ok = (c == LBRACKET) | (c == COMMA);
            }
        }
    }
    assert(found & ok, "element is not preceded by [ or ,");
}

// Proves body[value_offset .. value_offset + value_len] is the whole value at
// `path` (see the header). The value and the byte that closes it lie inside the
// prefix.
pub fn bind_path<let M: u32, let N: u32>(
    body: [u8; M],
    body_len: u32,
    st: JsonState<N>,
    root: u32,
    path: Path,
    h: Hint,
    kind: u32,
) -> [u8; VAL_MAX] {
    bind_path_upto::<SEG_MAX, M, N>(body, body_len, st, root, path, h, kind)
}

// bind_path over the first K segment slots only (K = 1 for the nullifier's top-level
// member, which saves the unused slots' constraints). Slots past K must be empty.
fn bind_path_upto<let K: u32, let M: u32, let N: u32>(
    body: [u8; M],
    body_len: u32,
    st: JsonState<N>,
    root: u32,
    path: Path,
    h: Hint,
    kind: u32,
) -> [u8; VAL_MAX] {
    assert((path.n >= 1) & (path.n <= K), "bad path length");
    assert((kind == KIND_STRING) | (kind == KIND_LITERAL), "unknown value kind");
    // The container of the current segment: the root bracket first.
    let mut c: u32 = root;
    for s in 0..K {
        let kind_s = path.kinds[s];
        if s < path.n {
            let t = h.tok[s];
            assert(t < body_len, "segment token past prefix");
            assert(h.open[s] < body_len, "segment value past prefix");
            assert(cont_at(st, t) == c, "segment is not directly inside the previous value");
            if kind_s == SEG_KEY {
                assert(body[c] == LBRACE, "key segment applied to a non-object");
                check_key_token(body, st, t, path.keys[s], path.lens[s]);
                check_sep(body, t + path.lens[s] + 2, h.open[s]);
            } else {
                assert(kind_s == SEG_ANY, "unknown segment kind");
                assert(body[c] == LBRACKET, "element segment applied to a non-array");
                assert(path.lens[s] == 0, "element segment has a key");
                for j in 0..KEY_MAX {
                    assert(path.keys[s][j] == 0, "element segment has a key");
                }
                assert(h.open[s] == t, "element value is not its token");
                assert(!in_str_at(st, t), "element is inside a string");
                let b = body[t];
                assert(
                    (b != COMMA) & (b != RBRACKET) & (b != RBRACE) & (b != COLON) & !is_ws(b),
                    "element token is not a value",
                );
                if (b != LBRACE) & (b != LBRACKET) & (b != QUOTE) {
                    check_elem_delim(body, t);
                }
            }
            // The next segment lives in this segment's value.
            if s + 1 < path.n {
                let next = path.kinds[if s + 1 < SEG_MAX { s + 1 } else { s }];
                let ob = body[h.open[s]];
                if next == SEG_KEY {
                    assert(ob == LBRACE, "key follows a value that is not an object");
                } else {
                    assert(ob == LBRACKET, "element follows a value that is not an array");
                }
            }
            c = h.open[s];
        } else {
            assert((kind_s == SEG_NONE) & (path.lens[s] == 0), "segment past the path length");
            assert((h.tok[s] == 0) & (h.open[s] == 0), "hint past the path length");
            for j in 0..KEY_MAX {
                assert(path.keys[s][j] == 0, "segment past the path length");
            }
        }
    }

    // The final value starts at c, the last segment's value token.
    let value_offset = h.value_offset;
    let value_len = h.value_len;
    assert((value_len >= 1) & (value_len <= VAL_MAX), "bad value length");
    assert(value_offset + value_len < body_len, "value runs past prefix");
    let is_str = kind == KIND_STRING;
    assert(value_offset >= 1, "value offset before key");
    let token = if is_str { value_offset - 1 } else { value_offset };
    assert(token == c, "value is not the last segment's value");

    let mut value: [u8; VAL_MAX] = [0; VAL_MAX];
    for i in 0..VAL_MAX {
        if i < value_len {
            let ch = body[value_offset + i];
            assert((ch != QUOTE) & (ch != BACKSLASH), "value contains a quote or backslash");
            if kind == KIND_LITERAL {
                assert(
                    (ch != COMMA)
                        & (ch != RBRACE)
                        & (ch != RBRACKET)
                        & (ch != LBRACE)
                        & (ch != LBRACKET)
                        & (ch != COLON)
                        & (ch > 32),
                    "bad literal byte",
                );
            }
            value[i] = ch;
        }
    }
    let end = body[value_offset + value_len];
    if is_str {
        assert(body[token] == QUOTE, "value is not a string");
        assert(end == QUOTE, "value not closed");
    } else {
        assert(body[token] != QUOTE, "value is a string");
        assert(
            (end == COMMA) | (end == RBRACE) | (end == RBRACKET) | is_ws(end),
            "literal not closed",
        );
    }
    value
}

fn apply_operator(
    op: u32,
    value: [u8; VAL_MAX],
    value_len: u32,
    operand: [u8; VAL_MAX],
    operand_len: u32,
    py: u32,
    pm: u32,
    pd: u32,
) -> bool {
    assert(op <= OP_LAST, "unknown operator");
    assert(operand_len <= VAL_MAX, "operand too long");
    for i in 0..VAL_MAX {
        if i >= operand_len {
            assert(operand[i] == 0, "operand padding not zero");
        }
    }
    let mut result = false;
    if op == OP_EQ {
        result = bytes_equal(value, value_len, operand, operand_len);
    } else if op == OP_NEQ {
        result = !bytes_equal(value, value_len, operand, operand_len);
    } else if op == OP_AGE_GTE {
        let threshold = parse_int(operand, 0, operand_len);
        result = age_years(value, value_len, py, pm, pd) >= threshold;
    } else if op == OP_RANGE_MIN_GTE {
        let threshold = parse_int(operand, 0, operand_len);
        result = range_min(value, value_len) >= threshold;
    } else if op == OP_ENDS_WITH {
        result = ends_with(value, value_len, operand, operand_len);
    } else if op == OP_DATE_BEFORE {
        result = date_key(value, value_len) < date_key(operand, operand_len);
    } else if op == OP_CONTAINS {
        result = contains(value, value_len, operand, operand_len);
    } else if op == OP_IN {
        result = one_of(value, value_len, operand, operand_len);
    } else {
        let v = parse_int(value, 0, value_len);
        let e = parse_int(operand, 0, operand_len);
        if op == OP_GT {
            result = v > e;
        } else if op == OP_LT {
            result = v < e;
        } else if op == OP_GTE {
            result = v >= e;
        } else {
            assert(op == OP_LTE);
            result = v <= e;
        }
    }
    result
}

fn bytes_equal(a: [u8; VAL_MAX], a_len: u32, b: [u8; VAL_MAX], b_len: u32) -> bool {
    let mut eq = a_len == b_len;
    for i in 0..VAL_MAX {
        if (i < a_len) & (a[i] != b[i]) {
            eq = false;
        }
    }
    eq
}

// The value's last operand_len bytes equal the operand, e.g. an email ending
// in "@example.com". An empty operand is refused: it would match anything.
fn ends_with(value: [u8; VAL_MAX], value_len: u32, operand: [u8; VAL_MAX], operand_len: u32) -> bool {
    assert(operand_len >= 1, "empty suffix");
    let mut ok = operand_len <= value_len;
    let start = if ok { value_len - operand_len } else { 0 };
    for i in 0..VAL_MAX {
        if i < operand_len {
            let idx = start + i;
            let v = value[if idx < VAL_MAX { idx } else { 0 }];
            if v != operand[i] {
                ok = false;
            }
        }
    }
    ok
}

// YYYY-MM-DD at the start of a date or an ISO-8601 timestamp (e.g. GitHub's
// "2014-05-01T12:34:56Z") as one sortable number YYYYMMDD. Anything after the
// date must start with 'T'.
fn date_key(v: [u8; VAL_MAX], len: u32) -> u64 {
    assert(len >= 10, "date must start with YYYY-MM-DD");
    assert((v[4] == DASH) & (v[7] == DASH), "date must start with YYYY-MM-DD");
    if len > 10 {
        assert(v[10] == 84, "date must be YYYY-MM-DD or YYYY-MM-DDT...");
    }
    let y = parse_int(v, 0, 4);
    let m = parse_int(v, 5, 2);
    let d = parse_int(v, 8, 2);
    assert(y > 0, "year missing (0000)");
    assert((m >= 1) & (m <= 12), "bad month");
    assert((d >= 1) & (d <= 31), "bad day");
    y * 10000 + m * 100 + d
}

fn parse_int(bytes: [u8; VAL_MAX], start: u32, len: u32) -> u64 {
    assert(len >= 1, "empty number");
    assert(len <= 18, "number too long");
    let mut v: u64 = 0;
    for i in 0..VAL_MAX {
        if (i >= start) & (i < start + len) {
            let d = bytes[i];
            assert((d >= 48) & (d <= 57), "not a digit");
            v = v * 10 + (d - 48) as u64;
        }
    }
    v
}

// Lower bound of an age range written `<min>~<max>` or `<min>~`, e.g. "30~39", "90~".
fn range_min(value: [u8; VAL_MAX], value_len: u32) -> u64 {
    let mut seen_tilde = false;
    let mut min: u64 = 0;
    let mut min_digits: u32 = 0;
    for i in 0..VAL_MAX {
        if i < value_len {
            let c = value[i];
            if c == TILDE {
                assert(!seen_tilde, "range has two tildes");
                seen_tilde = true;
            } else {
                assert((c >= 48) & (c <= 57), "not a digit");
                if !seen_tilde {
                    min = min * 10 + (c - 48) as u64;
                    min_digits += 1;
                }
            }
        }
    }
    assert(seen_tilde, "range has no tilde");
    assert((min_digits >= 1) & (min_digits <= 3), "bad range lower bound");
    min
}

// Age in whole years on the proof date.
//   YYYY-MM-DD: completed years (one less if the birthday has not come yet this year).
//   YYYY:       proof year minus birth year, i.e. the age reached during the proof year.
// A birth year of 0000 (birthday shared without the year) is rejected.
fn age_years(value: [u8; VAL_MAX], value_len: u32, py: u32, pm: u32, pd: u32) -> u64 {
    assert((value_len == 10) | (value_len == 4), "date must be YYYY-MM-DD or YYYY");
    let by = parse_int(value, 0, 4);
    assert(by > 0, "birth year missing (0000)");
    let py = py as u64;
    assert(py >= by, "birth year after proof year");
    let mut age = py - by;
    if value_len == 10 {
        assert((value[4] == DASH) & (value[7] == DASH), "date must be YYYY-MM-DD");
        let bm = parse_int(value, 5, 2);
        let bd = parse_int(value, 8, 2);
        assert((bm >= 1) & (bm <= 12), "bad birth month");
        assert((bd >= 1) & (bd <= 31), "bad birth day");
        let before_birthday = ((pm as u64) < bm) | (((pm as u64) == bm) & ((pd as u64) < bd));
        if before_birthday {
            assert(age >= 1, "birth date after proof date");
            age -= 1;
        }
    }
    age
}


// The operand occurs somewhere in the value. An empty operand is refused.
fn contains(value: [u8; VAL_MAX], value_len: u32, operand: [u8; VAL_MAX], operand_len: u32) -> bool {
    assert(operand_len >= 1, "empty substring");
    let mut found = false;
    for p in 0..VAL_MAX {
        if p + operand_len <= value_len {
            let mut m = true;
            for i in 0..VAL_MAX {
                if i < operand_len {
                    let idx = p + i;
                    if value[if idx < VAL_MAX { idx } else { 0 }] != operand[i] {
                        m = false;
                    }
                }
            }
            if m {
                found = true;
            }
        }
    }
    found
}

// The operand is a comma-separated list ("KR,JP,US"); the value equals one item.
// A value containing a comma is refused, so a match cannot straddle two items.
fn one_of(value: [u8; VAL_MAX], value_len: u32, operand: [u8; VAL_MAX], operand_len: u32) -> bool {
    assert(operand_len >= 1, "empty list");
    for i in 0..VAL_MAX {
        if i < value_len {
            assert(value[i] != COMMA, "value contains a comma");
        }
    }
    let mut found = false;
    for p in 0..VAL_MAX {
        let starts = (p == 0) | ((p > 0) & (operand[if p > 0 { p - 1 } else { 0 }] == COMMA));
        let end = p + value_len;
        let ends = (end == operand_len) | ((end < operand_len) & (operand[if end < VAL_MAX { end } else { 0 }] == COMMA));
        if starts & ends & (end <= operand_len) {
            let mut m = true;
            for i in 0..VAL_MAX {
                if i < value_len {
                    let idx = p + i;
                    if operand[if idx < VAL_MAX { idx } else { 0 }] != value[i] {
                        m = false;
                    }
                }
            }
            if m {
                found = true;
            }
        }
    }
    found
}

pub fn compute_nullifier(nf_value: [u8; VAL_MAX], nf_len: u32, scope: [u8; SCOPE_LEN]) -> [u8; 32] {
    let mut input: [u8; NF_LEN] = [0; NF_LEN];
    input[0] = nf_len as u8;
    for i in 0..VAL_MAX {
        input[1 + i] = nf_value[i];
    }
    for i in 0..SCOPE_LEN {
        input[1 + VAL_MAX + i] = scope[i];
    }
    keccak256(input, NF_LEN)
}

/// The same claim_hash for every capacity A: the encoding always has A_MAX
/// assertion slots, and slots A..A_MAX stay zero.
pub fn compute_claim_hash<let A: u32>(
    tier: u32,
    n_asserts: u32,
    asserts: [Assert; A],
    nf_key: [u8; KEY_MAX],
    nf_key_len: u32,
    nf_kind: u32,
    scope: [u8; SCOPE_LEN],
) -> [u8; 32] {
    std::static_assert(A <= A_MAX, "capacity above the claim encoding");
    let mut input: [u8; CLAIM_LEN] = [0; CLAIM_LEN];
    input[0] = CLAIM_VERSION;
    input[1] = (tier >> 8) as u8;
    input[2] = (tier & 0xff) as u8;
    input[3] = n_asserts as u8;
    for a in 0..A {
        let x = asserts[a];
        assert(x.path.n < 256, "path length out of range");
        assert(x.op < 256, "op code out of range");
        let base = 4 + a * ASSERT_ENC;
        input[base] = x.path.n as u8;
        for s in 0..SEG_MAX {
            let sb = base + 1 + s * SEG_ENC;
            input[sb] = x.path.kinds[s] as u8;
            input[sb + 1] = x.path.lens[s] as u8;
            for j in 0..KEY_MAX {
                input[sb + 2 + j] = x.path.keys[s][j];
            }
        }
        let pb = base + 1 + SEG_MAX * SEG_ENC;
        input[pb] = x.value_kind as u8;
        input[pb + 1] = x.op as u8;
        input[pb + 2] = x.operand_len as u8;
        for j in 0..VAL_MAX {
            input[pb + 3 + j] = x.operand[j];
        }
    }
    let nb = 4 + A_MAX * ASSERT_ENC;
    input[nb] = nf_key_len as u8;
    for j in 0..KEY_MAX {
        input[nb + 1 + j] = nf_key[j];
    }
    input[nb + 33] = nf_kind as u8;
    for j in 0..SCOPE_LEN {
        input[nb + 34 + j] = scope[j];
    }
    // SHA-256, not keccak: over 994 bytes it costs about half (64k gates against 142k
    // measured on the 1 KB tier), and every relying party has it.
    sha256_var(input, CLAIM_LEN)
}

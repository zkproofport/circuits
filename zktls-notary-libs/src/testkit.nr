// Helpers shared by the library tests and the tier packages' tests: path and
// claim builders, padding, hint derivation, and one call that runs a whole claim
// against a tier.

use crate::{
    A_MAX, Assert, BLINDER_LEN, compute_claim_hash, compute_nullifier, Hint, KEY_MAX, KIND_LITERAL,
    KIND_STRING, NF_NONE, OP_AGE_GTE, OP_RANGE_MIN_GTE, Path, SCOPE_LEN, SEG_ANY,
    SEG_KEY, SEG_MAX, SEG_NONE, top_path, VAL_MAX, verify_claim,
};
use crate::vectors::BLINDER;
use std::meta::ctstring::AsCtString;

// ---- Capacities --------------------------------------------------------

/// Runs one test at every circuit capacity A (1 to A_MAX) from `min` up: the
/// attributed function is generic over `let A: u32`, and this generates
/// `<name>_a1`, `<name>_a2`, `<name>_a3` (those >= min), each a #[test] calling
/// it with that A. `msg` is the expected failure, "" for a test that must pass.
/// `min` is the smallest capacity the test's claim fits: a claim that uses
/// assertion slot k (counting from 1) needs min >= k (fit_asserts refuses it below).
pub comptime fn capacities(f: FunctionDefinition, min: u32, msg: CtString) -> Quoted {
    let name = f.name();
    let mut out = quote {};
    for a in 1..A_MAX + 1 {
        if a >= min {
            let wrapper = f"{name}_a{a}".quoted_contents();
            let attr = if msg == "".as_ctstring() {
                quote { #[test] }
            } else {
                quote { #[test(should_fail_with = $msg)] }
            };
            out = quote { $out $attr fn $wrapper() { $name::<$a>() } };
        }
    }
    out
}

fn assert_is_empty(x: Assert) {
    let mut empty = (x.path.n == 0) & (x.value_kind == 0) & (x.op == 0) & (x.operand_len == 0);
    for s in 0..SEG_MAX {
        empty &= (x.path.kinds[s] == 0) & (x.path.lens[s] == 0);
        for j in 0..KEY_MAX {
            empty &= x.path.keys[s][j] == 0;
        }
    }
    for j in 0..VAL_MAX {
        empty &= x.operand[j] == 0;
    }
    assert(empty, "test claim does not fit this capacity");
}

/// A test claim's assertion slots as a capacity-A circuit takes them: the first A.
/// A claim with anything in a slot past A does not fit this capacity, and the test
/// says so rather than silently dropping it (the claim_hash still covers every slot).
pub fn fit_asserts<let A: u32>(x: [Assert; A_MAX]) -> [Assert; A] {
    let mut out = [no_assert(); A];
    for i in 0..A {
        out[i] = x[i];
    }
    for i in A..A_MAX {
        assert_is_empty(x[i]);
    }
    out
}

/// The first A hints. Hints past A are positions for slots this circuit does not
/// have; an honest capacity-A prover never sends them.
pub fn fit_hints<let A: u32>(h: [Hint; A_MAX]) -> [Hint; A] {
    let mut out = [zero_hint(); A];
    for i in 0..A {
        out[i] = h[i];
    }
    out
}

pub fn pad_to<let N: u32, let L: u32>(s: [u8; L], len: u32) -> [u8; N] {
    let mut out: [u8; N] = [0; N];
    for i in 0..N {
        if (i < L) & (i < len) {
            out[i] = s[i];
        }
    }
    out
}

pub fn pad32<let L: u32>(s: [u8; L]) -> [u8; 32] {
    let mut out: [u8; 32] = [0; 32];
    for i in 0..L {
        out[i] = s[i];
    }
    out
}

pub fn scope() -> [u8; SCOPE_LEN] {
    pad32("zkproofport:kakao-test".as_bytes())
}

// ---- Paths -------------------------------------------------------------

pub fn p_new() -> Path {
    Path { n: 0, kinds: [SEG_NONE; SEG_MAX], keys: [[0; KEY_MAX]; SEG_MAX], lens: [0; SEG_MAX] }
}

/// Appends an object key segment.
pub fn p_key<let L: u32>(p: Path, name: str<L>) -> Path {
    let mut q = p;
    q.kinds[p.n] = SEG_KEY;
    q.keys[p.n] = pad32(name.as_bytes());
    q.lens[p.n] = L;
    q.n = p.n + 1;
    q
}

/// Appends a `[]` (some element) segment.
pub fn p_any(p: Path) -> Path {
    let mut q = p;
    q.kinds[p.n] = SEG_ANY;
    q.n = p.n + 1;
    q
}

pub fn p1<let A: u32>(a: str<A>) -> Path {
    p_key(p_new(), a)
}

pub fn p2<let A: u32, let B: u32>(a: str<A>, b: str<B>) -> Path {
    p_key(p_key(p_new(), a), b)
}

/// `[].<key>`
pub fn p_elem<let A: u32>(a: str<A>) -> Path {
    p_key(p_any(p_new()), a)
}

// ---- Claims ------------------------------------------------------------

pub fn no_assert() -> Assert {
    Assert { path: p_new(), value_kind: 0, op: 0, operand: [0; VAL_MAX], operand_len: 0 }
}

pub fn assertion<let O: u32>(path: Path, kind: u32, op: u32, operand: str<O>) -> Assert {
    Assert { path, value_kind: kind, op, operand: pad32(operand.as_bytes()), operand_len: O }
}

// One claim: up to A_MAX assertions, the nullifier member and the value the
// prover holds for it, and the scope.
pub struct Claim {
    pub n: u32,
    pub asserts: [Assert; A_MAX],
    pub nf_key: [u8; KEY_MAX],
    pub nf_key_len: u32,
    pub nf_kind: u32,
    pub nf_value: [u8; VAL_MAX],
    pub nf_value_len: u32,
    pub scope: [u8; SCOPE_LEN],
}

pub fn single<let K: u32, let V: u32>(
    a: Assert,
    nf_key: str<K>,
    nf_kind: u32,
    nf_value: str<V>,
) -> Claim {
    let mut asserts = [no_assert(); A_MAX];
    asserts[0] = a;
    Claim {
        n: 1,
        asserts,
        nf_key: pad32(nf_key.as_bytes()),
        nf_key_len: K,
        nf_kind,
        nf_value: pad32(nf_value.as_bytes()),
        nf_value_len: V,
        scope: scope(),
    }
}

/// The same claim without an account member (NF_NONE).
pub fn without_nf(c: Claim) -> Claim {
    let mut d = c;
    d.nf_key = [0; KEY_MAX];
    d.nf_key_len = 0;
    d.nf_kind = NF_NONE;
    d.nf_value = [0; VAL_MAX];
    d.nf_value_len = 0;
    d
}

/// Adds an assertion to a claim.
pub fn and(c: Claim, a: Assert) -> Claim {
    let mut d = c;
    d.asserts[c.n] = a;
    d.n = c.n + 1;
    d
}

pub fn oidc_claim<let K: u32, let O: u32>(key: str<K>, kind: u32, op: u32, operand: str<O>) -> Claim {
    single(assertion(p1(key), kind, op, operand), "sub", KIND_STRING, "4012345678")
}

pub fn me_age_range_claim(min: str<2>) -> Claim {
    single(
        assertion(p2("kakao_account", "age_range"), KIND_STRING, OP_RANGE_MIN_GTE, min),
        "id",
        KIND_LITERAL,
        "1234567890",
    )
}

pub fn age19() -> Claim {
    oidc_claim("birthdate", KIND_STRING, OP_AGE_GTE, "19")
}

pub fn claim_hash_of(c: Claim, tier: u32) -> [u8; 32] {
    compute_claim_hash(tier, c.n, c.asserts, c.nf_key, c.nf_key_len, c.nf_kind, c.scope)
}

pub fn nullifier_of(c: Claim) -> [u8; 32] {
    compute_nullifier(c.nf_value, c.nf_value_len, c.scope)
}

// ---- Hints -------------------------------------------------------------

/// The first non-whitespace byte: where an honest prover says the root opens.
pub fn root_of<let L: u32>(b: [u8; L]) -> u32 {
    let mut r: u32 = 0;
    let mut found = false;
    for i in 0..L {
        if (!found) & !is_ws(b[i]) {
            r = i;
            found = true;
        }
    }
    r
}

fn is_ws(c: u8) -> bool {
    (c == 32) | (c == 9) | (c == 10) | (c == 13)
}

/// The innermost container before every byte, without the circuit's checks, so a
/// test helper never fails before the circuit gets to refuse an input.
pub unconstrained fn lenient_cont<let N: u32>(body: [u8; N], body_len: u32) -> [u32; N] {
    let mut cont: [u32; N] = [N; N];
    let mut stack: [u32; 256] = [0; 256];
    let (mut in_str, mut esc, mut depth, mut top) = (false, false, 0, N);
    for i in 0..N {
        cont[i] = top;
        if i < body_len {
            let c = body[i];
            if in_str {
                if esc {
                    esc = false;
                } else if c == 92 {
                    esc = true;
                } else if c == 34 {
                    in_str = false;
                }
            } else if c == 34 {
                in_str = true;
            } else if ((c == 123) | (c == 91)) & (depth < 256) {
                stack[depth] = i;
                depth += 1;
                top = i;
            } else if ((c == 125) | (c == 93)) & (depth > 0) {
                depth -= 1;
                top = if depth > 0 { stack[depth - 1] } else { N };
            }
        }
    }
    cont
}

/// What an honest prover would name for `path`, given only where its value sits:
/// walk from the value up through the innermost containers. For a value that is
/// not really at that path (the attack tests), the walk names whatever is there
/// and the circuit rejects it.
pub unconstrained fn derive_hint<let N: u32>(
    body: [u8; N],
    body_len: u32,
    path: Path,
    value_offset: u32,
    value_len: u32,
    kind: u32,
) -> Hint {
    let cont = lenient_cont(body, body_len);
    let mut h = Hint { tok: [0; SEG_MAX], open: [0; SEG_MAX], value_offset, value_len };
    let mut cur = if (kind == KIND_STRING) & (value_offset > 0) { value_offset - 1 } else { value_offset };
    // A value past the prefix: name it as is and let the circuit refuse it.
    if cur >= N {
        for s in 0..SEG_MAX {
            if s < path.n {
                h.open[s] = cur;
                h.tok[s] = cur;
            }
        }
    } else {
        for k in 0..SEG_MAX {
            if k < path.n {
                let s = path.n - 1 - k;
                h.open[s] = cur;
                if path.kinds[s] == SEG_KEY {
                    // Back over whitespace, the colon (and a backslash an escaped fake
                    // key would put before it) and whitespace to the key's closing
                    // quote, then to its opening quote.
                    let mut p = if cur > 0 { cur - 1 } else { 0 };
                    if (p > 0) & (body[p] == 92) {
                        p -= 1;
                    }
                    for _ in 0..16 {
                        if (p > 0) & is_ws(body[p]) {
                            p -= 1;
                        }
                    }
                    if (p > 0) & (body[p] == 58) {
                        p -= 1;
                    }
                    for _ in 0..16 {
                        if (p > 0) & is_ws(body[p]) {
                            p -= 1;
                        }
                    }
                    let mut q = if p > 0 { p - 1 } else { 0 };
                    for _ in 0..64 {
                        if (q > 0) & (body[q] != 34) {
                            q -= 1;
                        }
                    }
                    h.tok[s] = q;
                    let c = cont[q];
                    cur = if c < N { c } else { 0 };
                } else {
                    h.tok[s] = cur;
                    let c = cont[cur];
                    cur = if c < N { c } else { 0 };
                }
            }
        }
    }
    h
}

pub fn zero_hint() -> Hint {
    Hint { tok: [0; SEG_MAX], open: [0; SEG_MAX], value_offset: 0, value_len: 0 }
}

// Offsets into the body: where the value and the nullifier value start. `parent`
// is kept from the fixed-path tests for readability; hints are derived.
pub struct At {
    pub parent: u32,
    pub value: u32,
    pub value_len: u32,
    pub nf: u32,
}

pub fn at(parent: u32, value: u32, value_len: u32, nf: u32) -> At {
    At { parent, value, value_len, nf }
}

/// Every hint an honest prover gives for claim `c` with its first value at `a`.
pub fn hints_of<let N: u32, let L: u32>(body: str<L>, prefix_len: u32, c: Claim, a: At) -> ([Hint; A_MAX], Hint) {
    let padded: [u8; N] = pad_to(body.as_bytes(), prefix_len);
    let mut hints = [zero_hint(); A_MAX];
    // Safety: test-only hint derivation; the circuit checks every hint.
    hints[0] = unsafe { derive_hint(padded, prefix_len, c.asserts[0].path, a.value, a.value_len, c.asserts[0].value_kind) };
    let nf = if c.nf_kind == NF_NONE {
        zero_hint()
    } else {
        // Safety: as above.
        unsafe { derive_hint(padded, prefix_len, top_path(c.nf_key, c.nf_key_len), a.nf, c.nf_value_len, c.nf_kind) }
    };
    (hints, nf)
}

/// Runs one claim against tier N with every input given explicitly.
pub fn run_hints<let N: u32, let L: u32, let A: u32>(
    body: str<L>,
    prefix_len: u32,
    whole: bool,
    commitment: [u8; 32],
    blinder: [u8; BLINDER_LEN],
    c: Claim,
    hints: [Hint; A_MAX],
    nf_hint: Hint,
    claim_hash: [u8; 32],
    nullifier: [u8; 32],
) {
    verify_claim::<N, A>(
        pad_to(body.as_bytes(), prefix_len),
        prefix_len,
        blinder,
        root_of(body.as_bytes()),
        // Safety: test-only; the circuit checks every entry.
        unsafe { lenient_cont(pad_to(body.as_bytes(), prefix_len), prefix_len) },
        c.n,
        fit_asserts::<A>(c.asserts),
        fit_hints::<A>(hints),
        c.nf_key,
        c.nf_key_len,
        c.nf_kind,
        nf_hint,
        c.scope,
        commitment,
        whole,
        claim_hash,
        2026,
        11,
        16,
        nullifier,
    );
}

/// Every input explicit, including the root position, the container hint and the date.
pub fn run_all<let N: u32, let L: u32, let A: u32>(
    body: str<L>,
    prefix_len: u32,
    whole: bool,
    commitment: [u8; 32],
    c: Claim,
    hints: [Hint; A_MAX],
    nf_hint: Hint,
    root: u32,
    cont: [u32; N],
    date: [u32; 3],
) {
    verify_claim::<N, A>(
        pad_to(body.as_bytes(), prefix_len),
        prefix_len,
        BLINDER,
        root,
        cont,
        c.n,
        fit_asserts::<A>(c.asserts),
        fit_hints::<A>(hints),
        c.nf_key,
        c.nf_key_len,
        c.nf_kind,
        nf_hint,
        c.scope,
        commitment,
        whole,
        claim_hash_of(c, N),
        date[0],
        date[1],
        date[2],
        nullifier_of(c),
    );
}

/// The honest container hint for a body.
pub fn cont_of<let N: u32, let L: u32>(body: str<L>, prefix_len: u32) -> [u32; N] {
    // Safety: test-only; the circuit checks every entry.
    unsafe { lenient_cont(pad_to(body.as_bytes(), prefix_len), prefix_len) }
}

pub fn run_full<let N: u32, let L: u32, let A: u32>(
    body: str<L>,
    prefix_len: u32,
    whole: bool,
    commitment: [u8; 32],
    blinder: [u8; BLINDER_LEN],
    c: Claim,
    a: At,
    claim_hash: [u8; 32],
    nullifier: [u8; 32],
) {
    let (hints, nf) = hints_of::<N, L>(body, prefix_len, c, a);
    run_hints::<N, L, A>(body, prefix_len, whole, commitment, blinder, c, hints, nf, claim_hash, nullifier);
}

// Honest run of the whole body against tier N.
pub fn ok_whole<let N: u32, let L: u32, let A: u32>(body: str<L>, commitment: [u8; 32], c: Claim, a: At) {
    run_full::<N, L, A>(body, L, true, commitment, BLINDER, c, a, claim_hash_of(c, N), nullifier_of(c));
}

// Honest run of the first N bytes of a longer body against tier N.
pub fn ok_prefix<let N: u32, let L: u32, let A: u32>(body: str<L>, commitment: [u8; 32], c: Claim, a: At) {
    run_full::<N, L, A>(body, N, false, commitment, BLINDER, c, a, claim_hash_of(c, N), nullifier_of(c));
}

// Honest run of the whole body with explicit hints.
pub fn ok_hints<let N: u32, let L: u32, let A: u32>(
    body: str<L>,
    commitment: [u8; 32],
    c: Claim,
    hints: [Hint; A_MAX],
    nf: Hint,
) {
    run_hints::<N, L, A>(body, L, true, commitment, BLINDER, c, hints, nf, claim_hash_of(c, N), nullifier_of(c));
}

/// Hints for every assertion of `c`, each given where its value sits ([offset, len]).
pub fn hints_multi<let N: u32, let L: u32>(
    body: str<L>,
    prefix_len: u32,
    c: Claim,
    values: [[u32; 2]; A_MAX],
    nf_offset: u32,
) -> ([Hint; A_MAX], Hint) {
    let padded: [u8; N] = pad_to(body.as_bytes(), prefix_len);
    let mut hints = [zero_hint(); A_MAX];
    for a in 0..A_MAX {
        if a < c.n {
            // Safety: test-only hint derivation; the circuit checks every hint.
            hints[a] = unsafe { derive_hint(padded, prefix_len, c.asserts[a].path, values[a][0], values[a][1], c.asserts[a].value_kind) };
        }
    }
    let nf = if c.nf_kind == NF_NONE {
        zero_hint()
    } else {
        // Safety: as above.
        unsafe { derive_hint(padded, prefix_len, top_path(c.nf_key, c.nf_key_len), nf_offset, c.nf_value_len, c.nf_kind) }
    };
    (hints, nf)
}

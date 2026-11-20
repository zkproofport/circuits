// One test per guard that the claim tests never reach as the deciding check: each
// starts from honest inputs and breaks exactly the thing the guard is for. Found by
// the mutation check (a guard removed while every test still passed).

use crate::{
    A_MAX, Hint, KIND_LITERAL, KIND_STRING, OP_CONTAINS, OP_EQ, OP_IN, SEG_KEY, top_path,
};
use crate::testkit::capacities;
use crate::testkit::{
    assertion, Claim, cont_of, hints_multi, p1, p2, p_any, p_new, root_of, run_all, single,
    without_nf, zero_hint,
};
use crate::vectors_deep::{
    DEEP, DEEP_C, DEEP_DEPTH2, DEEP_ID, G_ARRS, G_ARRS_AB, G_ARRS_C, G_ARRS_N23, G_BLANK,
    G_BLANK_C, G_COMMA, G_COMMA_C, G_COMMA_V, G_OBJ, G_OBJ_A, G_OBJ_B, G_OBJ_C, G_OBJ_S, G_OBJ_T,
    G_ROOTARR, G_ROOTARR_C, G_ROOTARR_ZKP,
};

global T: u32 = 1024;
global DAY: [u32; 3] = [2026, 11, 16];

fn plain(a: crate::Assert) -> Claim {
    without_nf(single(a, "x", KIND_STRING, "x"))
}

fn honest<let L: u32>(body: str<L>, c: Claim, off: u32, len: u32, nf: u32) -> ([Hint; A_MAX], Hint) {
    hints_multi::<T, L>(body, L, c, [[off, len], [0, 0], [0, 0]], nf)
}

// Runs a whole body with the honest root and container hint.
fn go<let L: u32, let A: u32>(body: str<L>, commitment: [u8; 32], c: Claim, h: [Hint; A_MAX], nf: Hint) {
    run_all::<T, L, A>(body, L, true, commitment, c, h, nf, root_of(body.as_bytes()), cont_of(body, L), DAY);
}

fn a_is_x() -> Claim {
    plain(assertion(p1("a"), KIND_STRING, OP_EQ, "x"))
}

// ---- The scan and the root ----------------------------------------------------

#[capacities(1, "container hint mismatch")]
fn test_guard_container_hint_tampered<let A: u32>() {
    let c = a_is_x();
    let (h, nf) = honest(G_OBJ, c, G_OBJ_A, 1, 0);
    let mut cont = cont_of::<T, _>(G_OBJ, 42);
    cont[3] = 1;
    run_all::<T, _, A>(G_OBJ, 42, true, G_OBJ_C, c, h, nf, 0, cont, DAY);
}

#[capacities(1, "no root value")]
fn test_guard_whitespace_only_body<let A: u32>() {
    let c = a_is_x();
    run_all::<T, _, A>(G_BLANK, 3, true, G_BLANK_C, c, [zero_hint(); A_MAX], zero_hint(), 0, cont_of(G_BLANK, 3), DAY);
}

#[capacities(1, "root past prefix")]
fn test_guard_root_past_prefix<let A: u32>() {
    let c = a_is_x();
    let (h, nf) = honest(G_OBJ, c, G_OBJ_A, 1, 0);
    run_all::<T, _, A>(G_OBJ, 42, true, G_OBJ_C, c, h, nf, 42, cont_of(G_OBJ, 42), DAY);
}

#[capacities(1, "root is not an object or array")]
fn test_guard_root_not_a_bracket<let A: u32>() {
    let c = a_is_x();
    let (h, nf) = honest(G_OBJ, c, G_OBJ_A, 1, 0);
    run_all::<T, _, A>(G_OBJ, 42, true, G_OBJ_C, c, h, nf, 1, cont_of(G_OBJ, 42), DAY);
}

#[capacities(1, "root is inside a container")]
fn test_guard_root_is_a_nested_bracket<let A: u32>() {
    // The bracket opening "data"'s object is not the root.
    let c = single(assertion(p2("data", "login"), KIND_STRING, OP_EQ, "depth2"), "id", KIND_LITERAL, "7");
    let (h, nf) = honest(DEEP, c, DEEP_DEPTH2, 6, DEEP_ID);
    run_all::<T, _, A>(DEEP, DEEP.as_bytes().len(), true, DEEP_C, c, h, nf, 8, cont_of(DEEP, DEEP.as_bytes().len()), DAY);
}

// ---- Key segments --------------------------------------------------------------

#[capacities(1, "key does not start with a quote")]
fn test_guard_key_token_not_a_quote<let A: u32>() {
    let c = plain(assertion(p1("b"), KIND_LITERAL, OP_EQ, "7"));
    let (mut h, nf) = honest(G_OBJ, c, G_OBJ_B, 1, 0);
    h[0].tok[0] = G_OBJ_B; // the literal 7, directly inside the root
    go::<_, A>(G_OBJ, G_OBJ_C, c, h, nf);
}

#[capacities(1, "key not closed")]
fn test_guard_key_name_is_a_prefix<let A: u32>() {
    // "dat" against the key "data".
    let c = single(assertion(p2("dat", "login"), KIND_STRING, OP_EQ, "depth2"), "id", KIND_LITERAL, "7");
    let honest_c = single(assertion(p2("data", "login"), KIND_STRING, OP_EQ, "depth2"), "id", KIND_LITERAL, "7");
    let (h, nf) = honest(DEEP, honest_c, DEEP_DEPTH2, 6, DEEP_ID);
    go::<_, A>(DEEP, DEEP_C, c, h, nf);
}

#[capacities(1, "key contains a quote or backslash")]
fn test_guard_key_name_with_a_quote<let A: u32>() {
    let c = plain(assertion(p1("a\""), KIND_STRING, OP_EQ, "x"));
    let (h, nf) = honest(G_OBJ, a_is_x(), G_OBJ_A, 1, 0);
    go::<_, A>(G_OBJ, G_OBJ_C, c, h, nf);
}

#[capacities(1, "bad key length")]
fn test_guard_empty_key<let A: u32>() {
    let mut c = a_is_x();
    c.asserts[0].path.lens[0] = 0;
    c.asserts[0].path.keys[0] = [0; 32];
    let (h, nf) = honest(G_OBJ, a_is_x(), G_OBJ_A, 1, 0);
    go::<_, A>(G_OBJ, G_OBJ_C, c, h, nf);
}

#[capacities(1, "key padding not zero")]
fn test_guard_key_padding<let A: u32>() {
    let mut c = a_is_x();
    c.asserts[0].path.keys[0][5] = 1;
    let (h, nf) = honest(G_OBJ, a_is_x(), G_OBJ_A, 1, 0);
    go::<_, A>(G_OBJ, G_OBJ_C, c, h, nf);
}

#[capacities(1, "key segment applied to a non-object")]
fn test_guard_key_in_a_root_array<let A: u32>() {
    // ["login":"zkproofport"]: a key-shaped string directly in an array.
    let c = plain(assertion(p1("login"), KIND_STRING, OP_EQ, "zkproofport"));
    let mut h = [zero_hint(); A_MAX];
    h[0].tok[0] = 1;
    h[0].open[0] = 9;
    h[0].value_offset = G_ROOTARR_ZKP;
    h[0].value_len = 11;
    go::<_, A>(G_ROOTARR, G_ROOTARR_C, c, h, zero_hint());
}

// ---- Element segments -------------------------------------------------------------

#[capacities(1, "element segment applied to a non-array")]
fn test_guard_element_in_an_object<let A: u32>() {
    let c = plain(assertion(p_any(p_new()), KIND_STRING, OP_EQ, "x"));
    let mut h = [zero_hint(); A_MAX];
    h[0].tok[0] = G_OBJ_A - 1;
    h[0].open[0] = G_OBJ_A - 1;
    h[0].value_offset = G_OBJ_A;
    h[0].value_len = 1;
    go::<_, A>(G_OBJ, G_OBJ_C, c, h, zero_hint());
}

fn ab_is_elem() -> Claim {
    plain(assertion(p_any(p_new()), KIND_STRING, OP_EQ, "ab"))
}

#[capacities(1, "element segment has a key")]
fn test_guard_element_with_key_length<let A: u32>() {
    let mut c = ab_is_elem();
    c.asserts[0].path.lens[0] = 1;
    let (h, nf) = honest(G_ARRS, ab_is_elem(), G_ARRS_AB, 2, 0);
    go::<_, A>(G_ARRS, G_ARRS_C, c, h, nf);
}

#[capacities(1, "element value is not its token")]
fn test_guard_element_open_moved<let A: u32>() {
    let c = ab_is_elem();
    let (mut h, nf) = honest(G_ARRS, c, G_ARRS_AB, 2, 0);
    h[0].open[0] = h[0].tok[0] + 1;
    go::<_, A>(G_ARRS, G_ARRS_C, c, h, nf);
}

#[capacities(1, "element is inside a string")]
fn test_guard_element_inside_a_string<let A: u32>() {
    let c = ab_is_elem();
    let (mut h, nf) = honest(G_ARRS, c, G_ARRS_AB, 2, 0);
    h[0].tok[0] = G_ARRS_AB; // the "a" inside "ab"
    h[0].open[0] = G_ARRS_AB;
    go::<_, A>(G_ARRS, G_ARRS_C, c, h, nf);
}

#[capacities(1, "element is not preceded by [ or ,")]
fn test_guard_element_inside_a_literal<let A: u32>() {
    // [][]: the "3" of 23 is not an element.
    let c = plain(assertion(p_any(p_any(p_new())), KIND_LITERAL, OP_EQ, "3"));
    let honest_c = plain(assertion(p_any(p_any(p_new())), KIND_LITERAL, OP_EQ, "23"));
    let (mut h, nf) = honest(G_ARRS, honest_c, G_ARRS_N23, 2, 0);
    h[0].tok[1] = G_ARRS_N23 + 1;
    h[0].open[1] = G_ARRS_N23 + 1;
    h[0].value_offset = G_ARRS_N23 + 1;
    h[0].value_len = 1;
    go::<_, A>(G_ARRS, G_ARRS_C, c, h, nf);
}

// ---- Slots past the path, the value ----------------------------------------------

#[capacities(1, "segment past the path length")]
fn test_guard_segment_after_the_path<let A: u32>() {
    let mut c = a_is_x();
    c.asserts[0].path.kinds[1] = SEG_KEY;
    let (h, nf) = honest(G_OBJ, a_is_x(), G_OBJ_A, 1, 0);
    go::<_, A>(G_OBJ, G_OBJ_C, c, h, nf);
}

#[capacities(1, "hint past the path length")]
fn test_guard_hint_after_the_path<let A: u32>() {
    let c = a_is_x();
    let (mut h, nf) = honest(G_OBJ, c, G_OBJ_A, 1, 0);
    h[0].tok[1] = 5;
    go::<_, A>(G_OBJ, G_OBJ_C, c, h, nf);
}

#[capacities(1, "bad value length")]
fn test_guard_empty_value<let A: u32>() {
    let c = a_is_x();
    let (mut h, nf) = honest(G_OBJ, c, G_OBJ_A, 1, 0);
    h[0].value_len = 0;
    go::<_, A>(G_OBJ, G_OBJ_C, c, h, nf);
}

#[capacities(1, "value is not the last segment's value")]
fn test_guard_value_of_another_member<let A: u32>() {
    // The path names "a", the value bytes are "t"'s.
    let c = a_is_x();
    let (mut h, nf) = honest(G_OBJ, c, G_OBJ_A, 1, 0);
    h[0].value_offset = G_OBJ_T;
    go::<_, A>(G_OBJ, G_OBJ_C, c, h, nf);
}

#[capacities(1, "value contains a quote or backslash")]
fn test_guard_value_with_an_escape<let A: u32>() {
    // "zk\"q": reading "zk\" as the value.
    let c = plain(assertion(p1("s"), KIND_STRING, OP_EQ, "zk\\"));
    let (h, nf) = honest(G_OBJ, c, G_OBJ_S, 3, 0);
    go::<_, A>(G_OBJ, G_OBJ_C, c, h, nf);
}

#[capacities(1, "value is not a string")]
fn test_guard_literal_read_as_string<let A: u32>() {
    let c = plain(assertion(p1("b"), KIND_STRING, OP_EQ, "7"));
    let lit = plain(assertion(p1("b"), KIND_LITERAL, OP_EQ, "7"));
    let (mut h, nf) = honest(G_OBJ, lit, G_OBJ_B, 1, 0);
    h[0].value_offset = G_OBJ_B + 1; // the token is the 7, as for a string's opening quote
    go::<_, A>(G_OBJ, G_OBJ_C, c, h, nf);
}

// ---- Operators ---------------------------------------------------------------------

#[capacities(1, "empty substring")]
fn test_guard_contains_empty<let A: u32>() {
    let c = plain(assertion(p1("a"), KIND_STRING, OP_CONTAINS, ""));
    let (h, nf) = honest(G_OBJ, c, G_OBJ_A, 1, 0);
    go::<_, A>(G_OBJ, G_OBJ_C, c, h, nf);
}

#[capacities(1, "empty list")]
fn test_guard_in_empty<let A: u32>() {
    let c = plain(assertion(p1("a"), KIND_STRING, OP_IN, ""));
    let (h, nf) = honest(G_OBJ, c, G_OBJ_A, 1, 0);
    go::<_, A>(G_OBJ, G_OBJ_C, c, h, nf);
}

#[capacities(1, "value contains a comma")]
fn test_guard_in_value_with_a_comma<let A: u32>() {
    // "a,b" would otherwise match the two items of "a,b,c".
    let c = plain(assertion(p1("c"), KIND_STRING, OP_IN, "a,b,c"));
    let (h, nf) = honest(G_COMMA, c, G_COMMA_V, 3, 0);
    go::<_, A>(G_COMMA, G_COMMA_C, c, h, nf);
}

// ---- Unused slots, the nullifier, the claim header ------------------------------------

fn with_second(c: Claim) -> ([Hint; A_MAX], Hint) {
    honest(G_OBJ, c, G_OBJ_A, 1, 0)
}

#[capacities(2, "unused assertion has a segment")]
fn test_guard_unused_assertion_segment<let A: u32>() {
    let mut c = a_is_x();
    c.asserts[1].path.kinds[0] = SEG_KEY;
    let (h, nf) = with_second(a_is_x());
    go::<_, A>(G_OBJ, G_OBJ_C, c, h, nf);
}

#[capacities(2, "unused assertion has a key")]
fn test_guard_unused_assertion_key<let A: u32>() {
    let mut c = a_is_x();
    c.asserts[1].path.keys[0][0] = 97;
    let (h, nf) = with_second(a_is_x());
    go::<_, A>(G_OBJ, G_OBJ_C, c, h, nf);
}

#[capacities(2, "unused assertion has a predicate")]
fn test_guard_unused_assertion_predicate<let A: u32>() {
    let mut c = a_is_x();
    c.asserts[1].op = 1;
    let (h, nf) = with_second(a_is_x());
    go::<_, A>(G_OBJ, G_OBJ_C, c, h, nf);
}

#[capacities(2, "unused assertion has an operand")]
fn test_guard_unused_assertion_operand<let A: u32>() {
    let mut c = a_is_x();
    c.asserts[1].operand[0] = 1;
    let (h, nf) = with_second(a_is_x());
    go::<_, A>(G_OBJ, G_OBJ_C, c, h, nf);
}

#[capacities(1, "nullifier key padding not zero")]
fn test_guard_nullifier_key_without_kind<let A: u32>() {
    let mut c = a_is_x();
    c.nf_key[3] = 1;
    let (h, nf) = with_second(a_is_x());
    go::<_, A>(G_OBJ, G_OBJ_C, c, h, nf);
}

#[capacities(1, "bad assertion count")]
fn test_guard_no_assertion<let A: u32>() {
    let mut c = a_is_x();
    c.n = 0;
    let (h, nf) = with_second(a_is_x());
    go::<_, A>(G_OBJ, G_OBJ_C, c, h, nf);
}

#[capacities(1, "empty body")]
fn test_guard_one_byte_prefix<let A: u32>() {
    let c = a_is_x();
    let (h, nf) = with_second(c);
    run_all::<T, _, A>(G_OBJ, 1, true, G_OBJ_C, c, h, nf, 0, cont_of(G_OBJ, 1), DAY);
}

#[capacities(1, "bad proof month")]
fn test_guard_proof_month<let A: u32>() {
    let c = a_is_x();
    let (h, nf) = with_second(c);
    run_all::<T, _, A>(G_OBJ, 42, true, G_OBJ_C, c, h, nf, 0, cont_of(G_OBJ, 42), [2026, 13, 1]);
}

#[capacities(1, "bad proof day")]
fn test_guard_proof_day<let A: u32>() {
    let c = a_is_x();
    let (h, nf) = with_second(c);
    run_all::<T, _, A>(G_OBJ, 42, true, G_OBJ_C, c, h, nf, 0, cont_of(G_OBJ, 42), [2026, 11, 0]);
}

// ---- Operator helpers ------------------------------------------------------------

use crate::{OP_AGE_GTE, OP_DATE_BEFORE, OP_GT, OP_RANGE_MIN_GTE};
use crate::vectors_deep::{
    G_OPS, G_OPS_B1, G_OPS_BD, G_OPS_BDASH, G_OPS_BFIRST, G_OPS_BFUT, G_OPS_BM, G_OPS_C, G_OPS_D1,
    G_OPS_DD, G_OPS_DM, G_OPS_DZ, G_OPS_N, G_OPS_NLONG, G_OPS_NX, G_OPS_R2, G_OPS_R4, G_OPS_RX,
};

fn op_on<let K: u32, let O: u32, let A: u32>(key: str<K>, kind: u32, op: u32, operand: str<O>, off: u32, len: u32) {
    let c = plain(assertion(p1(key), kind, op, operand));
    let (h, nf) = honest(G_OPS, c, off, len, 0);
    go::<_, A>(G_OPS, G_OPS_C, c, h, nf);
}

#[capacities(1, "range has two tildes")]
fn test_guard_range_two_tildes<let A: u32>() {
    op_on::<_, _, A>("r2", KIND_STRING, OP_RANGE_MIN_GTE, "20", G_OPS_R2, 6);
}

#[capacities(1, "not a digit")]
fn test_guard_range_letter<let A: u32>() {
    op_on::<_, _, A>("rx", KIND_STRING, OP_RANGE_MIN_GTE, "20", G_OPS_RX, 5);
}

#[capacities(1, "bad range lower bound")]
fn test_guard_range_four_digits<let A: u32>() {
    op_on::<_, _, A>("r4", KIND_STRING, OP_RANGE_MIN_GTE, "20", G_OPS_R4, 5);
}

#[capacities(1, "date must start with YYYY-MM-DD")]
fn test_guard_date_too_short<let A: u32>() {
    op_on::<_, _, A>("d1", KIND_STRING, OP_DATE_BEFORE, "2020-01-01", G_OPS_D1, 9);
}

#[capacities(1, "year missing (0000)")]
fn test_guard_date_year_zero<let A: u32>() {
    op_on::<_, _, A>("dz", KIND_STRING, OP_DATE_BEFORE, "2020-01-01", G_OPS_DZ, 10);
}

#[capacities(1, "bad month")]
fn test_guard_date_month<let A: u32>() {
    op_on::<_, _, A>("dm", KIND_STRING, OP_DATE_BEFORE, "2021-01-01", G_OPS_DM, 10);
}

#[capacities(1, "bad day")]
fn test_guard_date_day<let A: u32>() {
    op_on::<_, _, A>("dd", KIND_STRING, OP_DATE_BEFORE, "2021-01-01", G_OPS_DD, 10);
}

#[capacities(1, "date must be YYYY-MM-DD or YYYY")]
fn test_guard_age_eight_digits<let A: u32>() {
    op_on::<_, _, A>("b1", KIND_STRING, OP_AGE_GTE, "19", G_OPS_B1, 8);
}

#[capacities(1, "birth year after proof year")]
fn test_guard_age_future_year<let A: u32>() {
    op_on::<_, _, A>("bfut", KIND_STRING, OP_AGE_GTE, "0", G_OPS_BFUT, 10);
}

#[capacities(1, "bad birth month")]
fn test_guard_age_month<let A: u32>() {
    op_on::<_, _, A>("bm", KIND_STRING, OP_AGE_GTE, "19", G_OPS_BM, 10);
}

#[capacities(1, "bad birth day")]
fn test_guard_age_day<let A: u32>() {
    op_on::<_, _, A>("bd", KIND_STRING, OP_AGE_GTE, "19", G_OPS_BD, 10);
}

#[capacities(1, "date must be YYYY-MM-DD")]
fn test_guard_age_slashes<let A: u32>() {
    op_on::<_, _, A>("bdash", KIND_STRING, OP_AGE_GTE, "19", G_OPS_BDASH, 10);
}

#[capacities(1, "birth date after proof date")]
fn test_guard_age_later_this_year<let A: u32>() {
    // Born 2026-12-01, proof date 2026-11-16: the birthday has not come, and age 0 - 1 is refused.
    op_on::<_, _, A>("bfirst", KIND_STRING, OP_AGE_GTE, "0", G_OPS_BFIRST, 10);
}

#[capacities(1, "empty number")]
fn test_guard_empty_operand_number<let A: u32>() {
    op_on::<_, _, A>("n", KIND_LITERAL, OP_GT, "", G_OPS_N, 2);
}

#[capacities(1, "number too long")]
fn test_guard_number_too_long<let A: u32>() {
    op_on::<_, _, A>("nlong", KIND_LITERAL, OP_GT, "1", G_OPS_NLONG, 19);
}

#[capacities(1, "not a digit")]
fn test_guard_number_with_a_letter<let A: u32>() {
    op_on::<_, _, A>("nx", KIND_STRING, OP_GT, "1", G_OPS_NX, 3);
}

#[capacities(1, "operand too long")]
fn test_guard_operand_length<let A: u32>() {
    let mut c = plain(assertion(p1("n"), KIND_LITERAL, OP_GT, "1"));
    c.asserts[0].operand_len = 33;
    let (h, nf) = honest(G_OPS, c, G_OPS_N, 2, 0);
    go::<_, A>(G_OPS, G_OPS_C, c, h, nf);
}

#[capacities(1, "operand padding not zero")]
fn test_guard_operand_padding<let A: u32>() {
    let mut c = plain(assertion(p1("n"), KIND_LITERAL, OP_GT, "1"));
    c.asserts[0].operand[10] = 1;
    let (h, nf) = honest(G_OPS, c, G_OPS_N, 2, 0);
    go::<_, A>(G_OPS, G_OPS_C, c, h, nf);
}

#[capacities(1, "segment past the path length")]
fn test_guard_key_after_the_path<let A: u32>() {
    let mut c = a_is_x();
    c.asserts[0].path.keys[1][0] = 97;
    let (h, nf) = honest(G_OBJ, a_is_x(), G_OBJ_A, 1, 0);
    go::<_, A>(G_OBJ, G_OBJ_C, c, h, nf);
}

#[capacities(1, "value offset before key")]
fn test_guard_value_at_byte_zero<let A: u32>() {
    let c = plain(assertion(p1("b"), KIND_LITERAL, OP_EQ, "7"));
    let (mut h, nf) = honest(G_OBJ, c, G_OBJ_B, 1, 0);
    h[0].value_offset = 0;
    go::<_, A>(G_OBJ, G_OBJ_C, c, h, nf);
}

// Silences an unused import when a guard test changes.
fn _unused(_: [u8; 32]) {
    let _ = top_path([0; 32], 0);
}

// General JSON paths: up to SEG_MAX segments of object keys and `[]` (some element),
// several assertions per claim, and the contains / in operators. Bodies, commitments
// and offsets are in vectors_deep.nr.

use crate::{KIND_LITERAL, KIND_STRING, OP_CONTAINS, OP_EQ, OP_GTE, OP_IN, Path};
use crate::testkit::capacities;
use crate::testkit::{
    and, assertion, at, Claim, hints_multi, ok_hints, ok_whole, p_any, p_key, p_new, single,
    without_nf,
};
use crate::vectors_deep::{
    ARR, ARR_C, ARR_ID, ARR_KR, ARR_N41, DEEP, DEEP_ALICE, DEEP_ARCHIVED, DEEP_C, DEEP_DEPTH2, DEEP_ID,
    DEEP_ITEMLOGIN, DEEP_PRETTY, DEEP_PRETTY_C, DEEP_PRETTY_ID, DEEP_PRETTY_ZKP, DEEP_SIBLING,
    DEEP_TYPE, DEEP_ZKP, EIGHT, EIGHT_C, EIGHT_ID, EIGHT_VAL, FAKE, FAKE_C, FAKE_F1, FAKE_F2,
    FAKE_F3, FAKE_HONEST, FAKE_ID, NESTED, NESTED_C, NESTED_ID, NESTED_TARGET, NESTED_X1,
    TOODEEP, TOODEEP_C, TOODEEP_ID,
};

global T: u32 = 1024;

// data.items[].owner.<leaf>
fn owner_path<let L: u32>(leaf: str<L>) -> Path {
    p_key(p_key(p_any(p_key(p_key(p_new(), "data"), "items")), "owner"), leaf)
}

fn login_is<let O: u32>(path: Path, operand: str<O>) -> Claim {
    single(assertion(path, KIND_STRING, OP_EQ, operand), "id", KIND_LITERAL, "7")
}

fn deep_login<let O: u32>(operand: str<O>) -> Claim {
    login_is(owner_path("login"), operand)
}

// ---- Honest deep paths ---------------------------------------------------

#[capacities(1, "")]
fn test_deep_owner_login_second_element<let A: u32>() {
    ok_whole::<T, _, A>(DEEP, DEEP_C, deep_login("zkproofport"), at(0, DEEP_ZKP, 11, DEEP_ID));
}

#[capacities(1, "")]
fn test_deep_owner_login_first_element<let A: u32>() {
    ok_whole::<T, _, A>(DEEP, DEEP_C, deep_login("alice"), at(0, DEEP_ALICE, 5, DEEP_ID));
}

#[capacities(1, "")]
fn test_deep_pretty_printed<let A: u32>() {
    ok_whole::<T, _, A>(DEEP_PRETTY, DEEP_PRETTY_C, deep_login("zkproofport"), at(0, DEEP_PRETTY_ZKP, 11, DEEP_PRETTY_ID));
}

#[capacities(1, "")]
fn test_nested_arrays_a_b_c<let A: u32>() {
    // a[].b[].c
    let path = p_key(p_any(p_key(p_any(p_key(p_new(), "a")), "b")), "c");
    let c = single(assertion(path, KIND_STRING, OP_EQ, "target"), "id", KIND_LITERAL, "9");
    ok_whole::<T, _, A>(NESTED, NESTED_C, c, at(0, NESTED_TARGET, 6, NESTED_ID));
}

#[capacities(1, "predicate does not hold")]
fn test_nested_arrays_other_element_value_fails<let A: u32>() {
    let path = p_key(p_any(p_key(p_any(p_key(p_new(), "a")), "b")), "c");
    let c = single(assertion(path, KIND_STRING, OP_EQ, "target"), "id", KIND_LITERAL, "9");
    ok_whole::<T, _, A>(NESTED, NESTED_C, c, at(0, NESTED_X1, 2, NESTED_ID));
}

fn eight_path() -> Path {
    let mut p = p_key(p_new(), "k1");
    p = p_key(p, "k2");
    p = p_key(p, "k3");
    p = p_key(p, "k4");
    p = p_key(p, "k5");
    p = p_key(p, "k6");
    p = p_key(p, "k7");
    p_key(p, "k8")
}

#[capacities(1, "")]
fn test_eight_segment_path<let A: u32>() {
    let c = single(assertion(eight_path(), KIND_STRING, OP_EQ, "deepvalue"), "id", KIND_LITERAL, "3");
    ok_whole::<T, _, A>(EIGHT, EIGHT_C, c, at(0, EIGHT_VAL, 9, EIGHT_ID));
}

#[capacities(1, "bad path length")]
fn test_nine_segments_refused<let A: u32>() {
    let mut c = single(assertion(eight_path(), KIND_STRING, OP_EQ, "deepvalue"), "id", KIND_LITERAL, "3");
    let (h, nf) = hints_multi::<T, _>(EIGHT, EIGHT.as_bytes().len(), c, [[EIGHT_VAL, 9], [0, 0], [0, 0]], EIGHT_ID);
    c.asserts[0].path.n = 9;
    ok_hints::<T, _, A>(EIGHT, EIGHT_C, c, h, nf);
}

// ---- Wrong place for the value --------------------------------------------

#[capacities(1, "segment is not directly inside the previous value")]
fn test_deep_same_key_at_wrong_depth_fails<let A: u32>() {
    // data.login, not data.items[].owner.login.
    ok_whole::<T, _, A>(DEEP, DEEP_C, deep_login("depth2"), at(0, DEEP_DEPTH2, 6, DEEP_ID));
}

#[capacities(1, "segment is not directly inside the previous value")]
fn test_deep_element_login_is_not_owner_login<let A: u32>() {
    // data.items[].login sits one level above data.items[].owner.login.
    ok_whole::<T, _, A>(DEEP, DEEP_C, deep_login("itemlogin"), at(0, DEEP_ITEMLOGIN, 9, DEEP_ID));
}

#[capacities(1, "segment is not directly inside the previous value")]
fn test_deep_key_in_sibling_object_fails<let A: u32>() {
    // data.other.owner.login
    ok_whole::<T, _, A>(DEEP, DEEP_C, deep_login("sibling"), at(0, DEEP_SIBLING, 7, DEEP_ID));
}

#[capacities(1, "key name mismatch")]
fn test_deep_element_of_other_array_fails<let A: u32>() {
    // data.archived[].owner.login
    ok_whole::<T, _, A>(DEEP, DEEP_C, deep_login("archivedorg"), at(0, DEEP_ARCHIVED, 11, DEEP_ID));
}

#[capacities(1, "element follows a value that is not an array")]
fn test_wildcard_applied_to_object_fails<let A: u32>() {
    // data.items[].owner[].login: owner is an object. The hint is the honest one for
    // data.items[].owner.login with the extra element pointed at the login key, the
    // only token directly inside owner's object.
    let honest = deep_login("zkproofport");
    let (h5, nf) = hints_multi::<T, _>(DEEP, DEEP.as_bytes().len(), honest, [[DEEP_ZKP, 11], [0, 0], [0, 0]], DEEP_ID);
    let path = p_key(p_any(p_key(p_any(p_key(p_key(p_new(), "data"), "items")), "owner")), "login");
    let c = login_is(path, "zkproofport");
    let mut h = h5;
    for s in 0..4 {
        h[0].tok[s] = h5[0].tok[s];
        h[0].open[s] = h5[0].open[s];
    }
    h[0].tok[4] = h5[0].tok[4];
    h[0].open[4] = h5[0].tok[4];
    h[0].tok[5] = h5[0].tok[4];
    h[0].open[5] = h5[0].open[4];
    ok_hints::<T, _, A>(DEEP, DEEP_C, c, h, nf);
}

#[capacities(1, "segment is not directly inside the previous value")]
fn test_key_applied_to_array_fails<let A: u32>() {
    // data.items.owner.login: items is an array.
    let path = p_key(p_key(p_key(p_key(p_new(), "data"), "items"), "owner"), "login");
    ok_whole::<T, _, A>(DEEP, DEEP_C, login_is(path, "zkproofport"), at(0, DEEP_ZKP, 11, DEEP_ID));
}

#[capacities(1, "segment is not directly inside the previous value")]
fn test_path_truncated_by_one_fails<let A: u32>() {
    // data.items[].owner: the value there is an object, not "zkproofport".
    let path = p_key(p_any(p_key(p_key(p_new(), "data"), "items")), "owner");
    ok_whole::<T, _, A>(DEEP, DEEP_C, login_is(path, "zkproofport"), at(0, DEEP_ZKP, 11, DEEP_ID));
}

#[capacities(1, "key quote is inside a string")]
fn test_path_extended_by_one_fails<let A: u32>() {
    // data.items[].owner.login.x
    let path = p_key(owner_path("login"), "x");
    ok_whole::<T, _, A>(DEEP, DEEP_C, login_is(path, "zkproofport"), at(0, DEEP_ZKP, 11, DEEP_ID));
}

// ---- Escaped fake keys inside strings, at every depth ------------------------

#[capacities(1, "")]
fn test_fake_body_honest_value<let A: u32>() {
    let c = single(assertion(owner_path("login"), KIND_STRING, OP_EQ, "honest"), "id", KIND_LITERAL, "5");
    ok_whole::<T, _, A>(FAKE, FAKE_C, c, at(0, FAKE_HONEST, 6, FAKE_ID));
}

#[capacities(1, "segment is not directly inside the previous value")]
fn test_fake_key_inside_top_level_string_fails<let A: u32>() {
    let c = single(assertion(owner_path("login"), KIND_STRING, OP_EQ, "zkproofport"), "id", KIND_LITERAL, "5");
    ok_whole::<T, _, A>(FAKE, FAKE_C, c, at(0, FAKE_F1, 11, FAKE_ID));
}

#[capacities(1, "segment is not directly inside the previous value")]
fn test_fake_key_inside_depth2_string_fails<let A: u32>() {
    let c = single(assertion(owner_path("login"), KIND_STRING, OP_EQ, "zkproofport"), "id", KIND_LITERAL, "5");
    ok_whole::<T, _, A>(FAKE, FAKE_C, c, at(0, FAKE_F2, 11, FAKE_ID));
}

#[capacities(1, "key quote is inside a string")]
fn test_fake_key_inside_depth4_string_fails<let A: u32>() {
    let c = single(assertion(owner_path("login"), KIND_STRING, OP_EQ, "zkproofport"), "id", KIND_LITERAL, "5");
    ok_whole::<T, _, A>(FAKE, FAKE_C, c, at(0, FAKE_F3, 11, FAKE_ID));
}

// ---- Array elements that are strings or literals -------------------------------

#[capacities(1, "")]
fn test_string_element<let A: u32>() {
    let c = single(assertion(p_any(p_key(p_new(), "tags")), KIND_STRING, OP_EQ, "kr"), "id", KIND_LITERAL, "8");
    ok_whole::<T, _, A>(ARR, ARR_C, c, at(0, ARR_KR, 2, ARR_ID));
}

#[capacities(1, "")]
fn test_literal_element<let A: u32>() {
    let c = single(assertion(p_any(p_key(p_new(), "nums")), KIND_LITERAL, OP_GTE, "40"), "id", KIND_LITERAL, "8");
    ok_whole::<T, _, A>(ARR, ARR_C, c, at(0, ARR_N41, 2, ARR_ID));
}

#[capacities(1, "")]
fn test_in_operator<let A: u32>() {
    let c = single(assertion(p_any(p_key(p_new(), "tags")), KIND_STRING, OP_IN, "us,jp,kr"), "id", KIND_LITERAL, "8");
    ok_whole::<T, _, A>(ARR, ARR_C, c, at(0, ARR_KR, 2, ARR_ID));
}

#[capacities(1, "predicate does not hold")]
fn test_in_operator_partial_item_fails<let A: u32>() {
    // "kr" is not an item of "us,jpkr,x".
    let c = single(assertion(p_any(p_key(p_new(), "tags")), KIND_STRING, OP_IN, "us,jpkr,x"), "id", KIND_LITERAL, "8");
    ok_whole::<T, _, A>(ARR, ARR_C, c, at(0, ARR_KR, 2, ARR_ID));
}

#[capacities(1, "")]
fn test_contains_operator<let A: u32>() {
    ok_whole::<T, _, A>(DEEP, DEEP_C, single(assertion(owner_path("login"), KIND_STRING, OP_CONTAINS, "proof"), "id", KIND_LITERAL, "7"), at(0, DEEP_ZKP, 11, DEEP_ID));
}

#[capacities(1, "predicate does not hold")]
fn test_contains_operator_missing_fails<let A: u32>() {
    ok_whole::<T, _, A>(DEEP, DEEP_C, single(assertion(owner_path("login"), KIND_STRING, OP_CONTAINS, "proofx"), "id", KIND_LITERAL, "7"), at(0, DEEP_ZKP, 11, DEEP_ID));
}

// ---- Several assertions, ANDed ------------------------------------------------

#[capacities(2, "")]
fn test_two_assertions<let A: u32>() {
    let c = and(deep_login("zkproofport"), assertion(owner_path("type"), KIND_STRING, OP_EQ, "Organization"));
    let (h, nf) = hints_multi::<T, _>(DEEP, DEEP.as_bytes().len(), c, [[DEEP_ZKP, 11], [DEEP_TYPE, 12], [0, 0]], DEEP_ID);
    ok_hints::<T, _, A>(DEEP, DEEP_C, c, h, nf);
}

#[capacities(2, "predicate does not hold")]
fn test_two_assertions_second_false_fails<let A: u32>() {
    let c = and(deep_login("zkproofport"), assertion(owner_path("type"), KIND_STRING, OP_EQ, "User"));
    let (h, nf) = hints_multi::<T, _>(DEEP, DEEP.as_bytes().len(), c, [[DEEP_ZKP, 11], [DEEP_TYPE, 12], [0, 0]], DEEP_ID);
    ok_hints::<T, _, A>(DEEP, DEEP_C, c, h, nf);
}

#[capacities(2, "unused assertion has a path")]
fn test_unused_assertion_slot_must_be_empty<let A: u32>() {
    let mut c = deep_login("zkproofport");
    c.asserts[1] = assertion(owner_path("type"), KIND_STRING, OP_EQ, "User");
    ok_whole::<T, _, A>(DEEP, DEEP_C, c, at(0, DEEP_ZKP, 11, DEEP_ID));
}

// ---- Limits --------------------------------------------------------------------

#[capacities(1, "")]
fn test_deep_nesting_elsewhere_is_fine<let A: u32>() {
    // 33 nested arrays in a member the claim does not read: the scan has no depth limit.
    let c = without_nf(single(assertion(p_key(p_new(), "id"), KIND_LITERAL, OP_EQ, "1"), "x", KIND_STRING, "x"));
    ok_whole::<T, _, A>(TOODEEP, TOODEEP_C, c, at(0, TOODEEP_ID, 1, 0));
}

// ---- The root value: object or array, whitespace around it, nothing else -------

use crate::vectors_deep::{
    ARR_ARR, ARR_ARR_C, ARR_ARR_TARGET, BOM_OBJ, BOM_OBJ_C, BOM_OBJ_ID, BOM_OBJ_V, CUT_ARR,
    CUT_ARR_C, CUT_ARR_ZKP, GARBAGE, GARBAGE_C, GARBAGE_ID, GARBAGE_V, SCALAR, SCALAR_C,
    TRAIL_X, TRAIL_X_C, TRAIL_X_ID, TRAIL_X_V, TWO_ROOTS, TWO_ROOTS_C, TWO_ROOTS_ID, TWO_ROOTS_V,
    WS_ARR, WS_ARR_C, WS_ARR_ZKP, WS_OBJ, WS_OBJ_C, WS_OBJ_ID, WS_OBJ_MILEAGE,
};
use crate::testkit::{p_elem, p2};

fn k_is_v() -> Claim {
    single(assertion(p_key(p_new(), "k"), KIND_STRING, OP_EQ, "v"), "id", KIND_LITERAL, "4")
}

fn org_is_zkp() -> Claim {
    without_nf(single(assertion(p_elem("login"), KIND_STRING, OP_EQ, "zkproofport"), "x", KIND_STRING, "x"))
}

#[capacities(1, "")]
fn test_root_object_with_whitespace_around<let A: u32>() {
    // "\r\n  \t{...} \n\n", the shape of a body that starts with whitespace.
    let c = single(assertion(p2("data", "mileage"), KIND_LITERAL, OP_GTE, "1000"), "id", KIND_LITERAL, "4");
    ok_whole::<T, _, A>(WS_OBJ, WS_OBJ_C, c, at(0, WS_OBJ_MILEAGE, 4, WS_OBJ_ID));
}

#[capacities(1, "")]
fn test_root_array_with_whitespace_around<let A: u32>() {
    ok_whole::<T, _, A>(WS_ARR, WS_ARR_C, org_is_zkp(), at(0, WS_ARR_ZKP, 11, 0));
}

#[capacities(1, "")]
fn test_root_array_of_arrays<let A: u32>() {
    // [][].c
    let path = p_key(p_any(p_any(p_new())), "c");
    let c = without_nf(single(assertion(path, KIND_STRING, OP_EQ, "target"), "x", KIND_STRING, "x"));
    ok_whole::<T, _, A>(ARR_ARR, ARR_ARR_C, c, at(0, ARR_ARR_TARGET, 6, 0));
}

#[capacities(1, "non-whitespace outside the root value")]
fn test_byte_order_mark_before_root_refused<let A: u32>() {
    // U+FEFF is not JSON whitespace (RFC 8259 section 2); the body is refused.
    ok_whole::<T, _, A>(BOM_OBJ, BOM_OBJ_C, k_is_v(), at(0, BOM_OBJ_V, 1, BOM_OBJ_ID));
}

#[capacities(1, "non-whitespace outside the root value")]
fn test_garbage_before_root_refused<let A: u32>() {
    ok_whole::<T, _, A>(GARBAGE, GARBAGE_C, k_is_v(), at(0, GARBAGE_V, 1, GARBAGE_ID));
}

#[capacities(1, "bytes after the root value")]
fn test_second_root_refused<let A: u32>() {
    ok_whole::<T, _, A>(TWO_ROOTS, TWO_ROOTS_C, k_is_v(), at(0, TWO_ROOTS_V, 1, TWO_ROOTS_ID));
}

#[capacities(1, "non-whitespace outside the root value")]
fn test_garbage_after_root_refused<let A: u32>() {
    ok_whole::<T, _, A>(TRAIL_X, TRAIL_X_C, k_is_v(), at(0, TRAIL_X_V, 1, TRAIL_X_ID));
}

#[capacities(1, "unbalanced JSON")]
fn test_cut_root_array_as_whole_refused<let A: u32>() {
    // The array never closes, so it cannot be presented as the whole body.
    ok_whole::<T, _, A>(CUT_ARR, CUT_ARR_C, org_is_zkp(), at(0, CUT_ARR_ZKP, 11, 0));
}

#[capacities(1, "non-whitespace outside the root value")]
fn test_root_scalar_refused<let A: u32>() {
    // A JSON text may be a bare scalar; no path can read into one, so the scan refuses
    // any root that is not an object or array.
    let c = without_nf(single(assertion(p_key(p_new(), "x"), KIND_LITERAL, OP_EQ, "true"), "x", KIND_STRING, "x"));
    ok_whole::<T, _, A>(SCALAR, SCALAR_C, c, at(0, 0, 4, 0));
}

use crate::vectors_deep::{MISMATCH, MISMATCH_C, MISMATCH_ID, MISMATCH_V};

#[capacities(1, "closing bracket does not match")]
fn test_mismatched_closing_bracket_refused<let A: u32>() {
    // {"id":4,"k":"v","x":[1}}: an array closed with a brace.
    ok_whole::<T, _, A>(MISMATCH, MISMATCH_C, k_is_v(), at(0, MISMATCH_V, 1, MISMATCH_ID));
}

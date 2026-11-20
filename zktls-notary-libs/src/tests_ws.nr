// Bodies shaped like other providers' responses: pretty-printed JSON (Google
// OpenID user info), a compact object with ISO timestamps (GitHub /user), and a
// top-level array of objects (GitHub /user/orgs). Run against a 1 KB tier.
// Bodies, commitments and offsets are in vectors_ws.nr.

use crate::{A_MAX, Hint, KIND_LITERAL, KIND_STRING, OP_DATE_BEFORE, OP_ENDS_WITH, OP_EQ, OP_GTE, SEG_KEY};
use crate::testkit::capacities;
use crate::testkit::{
    assertion, at, Claim, claim_hash_of, hints_of, nullifier_of, ok_hints, p1, p_elem, pad32,
    run_hints, single, without_nf,
};
use crate::vectors::BLINDER;
use crate::vectors_ws::{
    G_ARRSEP, G_ARRSEP_C, G_ARRSEP_EMAIL_K, G_ARRSEP_EMAIL_L, G_ARRSEP_EMAIL_V, G_ARRSEP_EVIL_L,
    G_ARRSEP_EVIL_V, G_ARRSEP_FAKE_K, G_ARRSEP_SUB_K, G_ARRSEP_SUB_V, G_FALSE, G_FALSE_C,
    G_FALSE_EV_K, G_FALSE_EV_L, G_FALSE_EV_V, G_FALSE_SUB_K, G_FALSE_SUB_V, G_GMAIL, G_GMAIL_C,
    G_GMAIL_EMAIL_K, G_GMAIL_EMAIL_L, G_GMAIL_EMAIL_V, G_GMAIL_EV_K, G_GMAIL_EV_L, G_GMAIL_EV_V,
    G_GMAIL_SUB_K, G_GMAIL_SUB_V, G_WIDE, G_WIDE_C, G_WIDE_EMAIL_K, G_WIDE_EMAIL_L,
    G_WIDE_EMAIL_V, G_WIDE_SUB_K, G_WIDE_SUB_V, G_WS, G_WS_C, G_WS_HD_K, G_WS_HD_L, G_WS_HD_V,
    G_WS_SUB_K, G_WS_SUB_V, GH_INNERARR, GH_INNERARR_C, GH_INNERARR_INNER_K, GH_INNERARR_INNER_L,
    GH_INNERARR_INNER_V, GH_NESTED, GH_NESTED_C, GH_NESTED_INNER_K, GH_NESTED_INNER_L,
    GH_NESTED_INNER_V, GH_OBJARR, GH_OBJARR_C, GH_OBJARR_LOGIN_K, GH_OBJARR_LOGIN_L,
    GH_OBJARR_LOGIN_V, GH_ORGS, GH_ORGS_ACME_K, GH_ORGS_ACME_L, GH_ORGS_ACME_V, GH_ORGS_C,
    GH_ORGS_PRETTY, GH_ORGS_PRETTY_C, GH_ORGS_PRETTY_ZKP_K, GH_ORGS_PRETTY_ZKP_L,
    GH_ORGS_PRETTY_ZKP_V, GH_ORGS_ZKP_K, GH_ORGS_ZKP_L, GH_ORGS_ZKP_V, GH_USER, GH_USER_C,
    GH_USER_CREATED_K, GH_USER_CREATED_L, GH_USER_CREATED_V, GH_USER_FOLLOWERS_K,
    GH_USER_FOLLOWERS_L, GH_USER_FOLLOWERS_V, GH_USER_ID_K, GH_USER_ID_V,
};

global T: u32 = 1024;

// A top-level member claim whose nullifier is a top-level member too.
fn top<let K: u32, let O: u32, let F: u32, let V: u32>(
    key: str<K>,
    kind: u32,
    op: u32,
    operand: str<O>,
    nf_key: str<F>,
    nf_kind: u32,
    nf_value: str<V>,
) -> Claim {
    single(assertion(p1(key), kind, op, operand), nf_key, nf_kind, nf_value)
}

// "Some element of the top-level array has <key> == operand", no account member.
fn elem<let K: u32, let O: u32>(key: str<K>, operand: str<O>) -> Claim {
    without_nf(single(assertion(p_elem(key), KIND_STRING, OP_EQ, operand), "x", KIND_STRING, "x"))
}

fn google<let K: u32, let O: u32>(key: str<K>, kind: u32, op: u32, operand: str<O>) -> Claim {
    top(key, kind, op, operand, "sub", KIND_STRING, "109876543210987654321")
}

fn github<let K: u32, let O: u32>(key: str<K>, kind: u32, op: u32, operand: str<O>) -> Claim {
    top(key, kind, op, operand, "id", KIND_LITERAL, "1234567")
}

// Where the claimed key and value (and the nullifier's) sit, as the fixed-path tests
// named them. The rest of the hint is derived from the value; the key offsets given
// here then replace the derived ones, so a test can point a key anywhere.
struct Loc {
    key: u32,
    value: u32,
    len: u32,
    nf_key: u32,
    nf: u32,
}

fn loc(key: u32, value: u32, len: u32, nf_key: u32, nf: u32, nf_len: u32) -> Loc {
    let _ = nf_len;
    Loc { key, value, len, nf_key, nf }
}

fn gsub(k: u32, v: u32, key: u32, value: u32, len: u32) -> Loc {
    loc(key, value, len, k, v, 21)
}

fn hints<let L: u32>(body: str<L>, c: Claim, l: Loc) -> ([Hint; A_MAX], Hint) {
    let (mut h, mut nf) = hints_of::<T, L>(body, L, c, at(0, l.value, l.len, l.nf));
    let last = c.asserts[0].path.n - 1;
    if c.asserts[0].path.kinds[last] == SEG_KEY {
        h[0].tok[last] = l.key;
    }
    if c.nf_key_len > 0 {
        nf.tok[0] = l.nf_key;
    }
    (h, nf)
}

fn ok_loc<let N: u32, let L: u32, let A: u32>(body: str<L>, commitment: [u8; 32], c: Claim, l: Loc) {
    let (h, nf) = hints(body, c, l);
    ok_hints::<N, L, A>(body, commitment, c, h, nf);
}

fn run_loc<let N: u32, let L: u32, let A: u32>(
    body: str<L>,
    prefix_len: u32,
    whole: bool,
    commitment: [u8; 32],
    blinder: [u8; 16],
    c: Claim,
    l: Loc,
    claim_hash: [u8; 32],
    nullifier: [u8; 32],
) {
    let (h, nf) = hints(body, c, l);
    run_hints::<N, L, A>(body, prefix_len, whole, commitment, blinder, c, h, nf, claim_hash, nullifier);
}

// ---- Pretty-printed object (Google OpenID user info) --------------------

#[capacities(1, "")]
fn test_ws_google_email_verified_true<let A: u32>() {
    ok_loc::<T, _, A>(
        G_GMAIL,
        G_GMAIL_C,
        google("email_verified", KIND_LITERAL, OP_EQ, "true"),
        gsub(G_GMAIL_SUB_K, G_GMAIL_SUB_V, G_GMAIL_EV_K, G_GMAIL_EV_V, G_GMAIL_EV_L),
    );
}

#[capacities(1, "predicate does not hold")]
fn test_ws_google_email_verified_false_fails<let A: u32>() {
    ok_loc::<T, _, A>(
        G_FALSE,
        G_FALSE_C,
        google("email_verified", KIND_LITERAL, OP_EQ, "true"),
        gsub(G_FALSE_SUB_K, G_FALSE_SUB_V, G_FALSE_EV_K, G_FALSE_EV_V, G_FALSE_EV_L),
    );
}

#[capacities(1, "literal not closed")]
fn test_ws_literal_read_partly_fails<let A: u32>() {
    // "tru" out of "true": the next byte is a letter, not a terminator.
    ok_loc::<T, _, A>(
        G_GMAIL,
        G_GMAIL_C,
        google("email_verified", KIND_LITERAL, OP_EQ, "tru"),
        gsub(G_GMAIL_SUB_K, G_GMAIL_SUB_V, G_GMAIL_EV_K, G_GMAIL_EV_V, G_GMAIL_EV_L - 1),
    );
}

#[capacities(1, "")]
fn test_ws_google_email_ends_with_domain<let A: u32>() {
    ok_loc::<T, _, A>(
        G_GMAIL,
        G_GMAIL_C,
        google("email", KIND_STRING, OP_ENDS_WITH, "@gmail.com"),
        gsub(G_GMAIL_SUB_K, G_GMAIL_SUB_V, G_GMAIL_EMAIL_K, G_GMAIL_EMAIL_V, G_GMAIL_EMAIL_L),
    );
}

#[capacities(1, "predicate does not hold")]
fn test_ws_google_email_other_domain_fails<let A: u32>() {
    ok_loc::<T, _, A>(
        G_GMAIL,
        G_GMAIL_C,
        google("email", KIND_STRING, OP_ENDS_WITH, "@example.com"),
        gsub(G_GMAIL_SUB_K, G_GMAIL_SUB_V, G_GMAIL_EMAIL_K, G_GMAIL_EMAIL_V, G_GMAIL_EMAIL_L),
    );
}

#[capacities(1, "predicate does not hold")]
fn test_ws_suffix_longer_than_value_fails<let A: u32>() {
    ok_loc::<T, _, A>(
        G_GMAIL,
        G_GMAIL_C,
        google("email", KIND_STRING, OP_ENDS_WITH, "longer-than-the-email@gmail.com"),
        gsub(G_GMAIL_SUB_K, G_GMAIL_SUB_V, G_GMAIL_EMAIL_K, G_GMAIL_EMAIL_V, G_GMAIL_EMAIL_L),
    );
}

#[capacities(1, "empty suffix")]
fn test_ws_empty_suffix_fails<let A: u32>() {
    ok_loc::<T, _, A>(
        G_GMAIL,
        G_GMAIL_C,
        google("email", KIND_STRING, OP_ENDS_WITH, ""),
        gsub(G_GMAIL_SUB_K, G_GMAIL_SUB_V, G_GMAIL_EMAIL_K, G_GMAIL_EMAIL_V, G_GMAIL_EMAIL_L),
    );
}

#[capacities(1, "")]
fn test_ws_google_workspace_domain<let A: u32>() {
    ok_loc::<T, _, A>(
        G_WS,
        G_WS_C,
        google("hd", KIND_STRING, OP_EQ, "example.com"),
        gsub(G_WS_SUB_K, G_WS_SUB_V, G_WS_HD_K, G_WS_HD_V, G_WS_HD_L),
    );
}

#[capacities(1, "predicate does not hold")]
fn test_ws_google_workspace_other_domain_fails<let A: u32>() {
    ok_loc::<T, _, A>(
        G_WS,
        G_WS_C,
        google("hd", KIND_STRING, OP_EQ, "example.org"),
        gsub(G_WS_SUB_K, G_WS_SUB_V, G_WS_HD_K, G_WS_HD_V, G_WS_HD_L),
    );
}

#[capacities(1, "segment is not directly inside the previous value")]
fn test_ws_array_string_followed_by_comma_is_not_a_key<let A: u32>() {
    // ["email" , "evil@gmail.com"] is an array, not an email member.
    ok_loc::<T, _, A>(
        G_ARRSEP,
        G_ARRSEP_C,
        google("email", KIND_STRING, OP_ENDS_WITH, "@gmail.com"),
        gsub(G_ARRSEP_SUB_K, G_ARRSEP_SUB_V, G_ARRSEP_FAKE_K, G_ARRSEP_EVIL_V, G_ARRSEP_EVIL_L),
    );
}

#[capacities(1, "")]
fn test_ws_real_member_after_array_string<let A: u32>() {
    ok_loc::<T, _, A>(
        G_ARRSEP,
        G_ARRSEP_C,
        google("email", KIND_STRING, OP_ENDS_WITH, "@other.com"),
        gsub(G_ARRSEP_SUB_K, G_ARRSEP_SUB_V, G_ARRSEP_EMAIL_K, G_ARRSEP_EMAIL_V, G_ARRSEP_EMAIL_L),
    );
}

#[capacities(1, "too much whitespace after key")]
fn test_ws_separator_wider_than_limit_fails<let A: u32>() {
    ok_loc::<T, _, A>(
        G_WIDE,
        G_WIDE_C,
        google("email", KIND_STRING, OP_ENDS_WITH, "@gmail.com"),
        gsub(G_WIDE_SUB_K, G_WIDE_SUB_V, G_WIDE_EMAIL_K, G_WIDE_EMAIL_V, G_WIDE_EMAIL_L),
    );
}

#[capacities(1, "key name mismatch")]
fn test_ws_key_offset_on_other_key_fails<let A: u32>() {
    // The key offset points at "sub" while the schema says "email".
    ok_loc::<T, _, A>(
        G_GMAIL,
        G_GMAIL_C,
        google("email", KIND_STRING, OP_ENDS_WITH, "@gmail.com"),
        gsub(G_GMAIL_SUB_K, G_GMAIL_SUB_V, G_GMAIL_SUB_K, G_GMAIL_EMAIL_V, G_GMAIL_EMAIL_L),
    );
}

#[capacities(1, "no colon after key")]
fn test_ws_value_offset_not_after_its_key_fails<let A: u32>() {
    // The key is "email" but the value offset is the sub's value.
    ok_loc::<T, _, A>(
        G_GMAIL,
        G_GMAIL_C,
        google("email", KIND_STRING, OP_EQ, "109876543210987654321"),
        gsub(G_GMAIL_SUB_K, G_GMAIL_SUB_V, G_GMAIL_EMAIL_K, G_GMAIL_SUB_V, 21),
    );
}

// ---- Compact object with timestamps (GitHub /user) ----------------------

fn ghloc(key: u32, value: u32, len: u32) -> Loc {
    loc(key, value, len, GH_USER_ID_K, GH_USER_ID_V, 7)
}

#[capacities(1, "")]
fn test_gh_followers_at_least_10<let A: u32>() {
    ok_loc::<T, _, A>(
        GH_USER,
        GH_USER_C,
        github("followers", KIND_LITERAL, OP_GTE, "10"),
        ghloc(GH_USER_FOLLOWERS_K, GH_USER_FOLLOWERS_V, GH_USER_FOLLOWERS_L),
    );
}

#[capacities(1, "")]
fn test_gh_created_before_2020<let A: u32>() {
    ok_loc::<T, _, A>(
        GH_USER,
        GH_USER_C,
        github("created_at", KIND_STRING, OP_DATE_BEFORE, "2020-01-01"),
        ghloc(GH_USER_CREATED_K, GH_USER_CREATED_V, GH_USER_CREATED_L),
    );
}

#[capacities(1, "predicate does not hold")]
fn test_gh_created_before_2010_fails<let A: u32>() {
    ok_loc::<T, _, A>(
        GH_USER,
        GH_USER_C,
        github("created_at", KIND_STRING, OP_DATE_BEFORE, "2010-01-01"),
        ghloc(GH_USER_CREATED_K, GH_USER_CREATED_V, GH_USER_CREATED_L),
    );
}

#[capacities(1, "predicate does not hold")]
fn test_gh_created_same_day_is_not_before<let A: u32>() {
    ok_loc::<T, _, A>(
        GH_USER,
        GH_USER_C,
        github("created_at", KIND_STRING, OP_DATE_BEFORE, "2014-05-01"),
        ghloc(GH_USER_CREATED_K, GH_USER_CREATED_V, GH_USER_CREATED_L),
    );
}

#[capacities(1, "date must start with YYYY-MM-DD")]
fn test_gh_date_operand_in_other_format_fails<let A: u32>() {
    ok_loc::<T, _, A>(
        GH_USER,
        GH_USER_C,
        github("created_at", KIND_STRING, OP_DATE_BEFORE, "2020/01/01"),
        ghloc(GH_USER_CREATED_K, GH_USER_CREATED_V, GH_USER_CREATED_L),
    );
}

// ---- Top-level array of objects (GitHub /user/orgs) ---------------------

fn eloc(key: u32, value: u32, len: u32) -> Loc {
    loc(key, value, len, 0, 0, 0)
}

#[capacities(1, "")]
fn test_gh_org_second_element<let A: u32>() {
    ok_loc::<T, _, A>(GH_ORGS, GH_ORGS_C, elem("login", "zkproofport"), eloc(GH_ORGS_ZKP_K, GH_ORGS_ZKP_V, GH_ORGS_ZKP_L));
}

#[capacities(1, "")]
fn test_gh_org_first_element<let A: u32>() {
    ok_loc::<T, _, A>(GH_ORGS, GH_ORGS_C, elem("login", "acme"), eloc(GH_ORGS_ACME_K, GH_ORGS_ACME_V, GH_ORGS_ACME_L));
}

#[capacities(1, "")]
fn test_gh_org_pretty_printed_array<let A: u32>() {
    ok_loc::<T, _, A>(
        GH_ORGS_PRETTY,
        GH_ORGS_PRETTY_C,
        elem("login", "zkproofport"),
        eloc(GH_ORGS_PRETTY_ZKP_K, GH_ORGS_PRETTY_ZKP_V, GH_ORGS_PRETTY_ZKP_L),
    );
}

#[capacities(1, "predicate does not hold")]
fn test_gh_org_other_element_fails<let A: u32>() {
    ok_loc::<T, _, A>(GH_ORGS, GH_ORGS_C, elem("login", "zkproofport"), eloc(GH_ORGS_ACME_K, GH_ORGS_ACME_V, GH_ORGS_ACME_L));
}

#[capacities(1, "segment is not directly inside the previous value")]
fn test_gh_org_login_inside_nested_object_fails<let A: u32>() {
    // [{"login":"other","owner":{"login":"zkproofport"}}]
    ok_loc::<T, _, A>(
        GH_NESTED,
        GH_NESTED_C,
        elem("login", "zkproofport"),
        eloc(GH_NESTED_INNER_K, GH_NESTED_INNER_V, GH_NESTED_INNER_L),
    );
}

#[capacities(1, "segment is not directly inside the previous value")]
fn test_gh_org_login_inside_inner_array_fails<let A: u32>() {
    // [{"teams":[{"login":"zkproofport"}],"login":"other"}]
    ok_loc::<T, _, A>(
        GH_INNERARR,
        GH_INNERARR_C,
        elem("login", "zkproofport"),
        eloc(GH_INNERARR_INNER_K, GH_INNERARR_INNER_V, GH_INNERARR_INNER_L),
    );
}

#[capacities(1, "segment is not directly inside the previous value")]
fn test_gh_element_path_on_object_body_fails<let A: u32>() {
    // {"orgs":[{"login":"zkproofport"}],"id":5}: an array inside an object.
    ok_loc::<T, _, A>(
        GH_OBJARR,
        GH_OBJARR_C,
        elem("login", "zkproofport"),
        eloc(GH_OBJARR_LOGIN_K, GH_OBJARR_LOGIN_V, GH_OBJARR_LOGIN_L),
    );
}

#[capacities(1, "segment is not directly inside the previous value")]
fn test_top_path_on_array_body_fails<let A: u32>() {
    let mut c = elem("login", "zkproofport");
    c.asserts[0].path = p1("login");
    ok_loc::<T, _, A>(GH_ORGS, GH_ORGS_C, c, eloc(GH_ORGS_ZKP_K, GH_ORGS_ZKP_V, GH_ORGS_ZKP_L));
}

#[capacities(1, "NF_NONE takes no nullifier key")]
fn test_nf_none_with_a_key_fails<let A: u32>() {
    let mut c = elem("login", "zkproofport");
    c.nf_key = pad32("id".as_bytes());
    c.nf_key_len = 2;
    ok_loc::<T, _, A>(GH_ORGS, GH_ORGS_C, c, eloc(GH_ORGS_ZKP_K, GH_ORGS_ZKP_V, GH_ORGS_ZKP_L));
}

#[capacities(1, "element segment has a key")]
fn test_element_segment_with_a_key_fails<let A: u32>() {
    let mut c = elem("login", "zkproofport");
    c.asserts[0].path.keys[0] = pad32("orgs".as_bytes());
    ok_loc::<T, _, A>(GH_ORGS, GH_ORGS_C, c, eloc(GH_ORGS_ZKP_K, GH_ORGS_ZKP_V, GH_ORGS_ZKP_L));
}

#[capacities(1, "unknown segment kind")]
fn test_unknown_segment_kind_fails<let A: u32>() {
    let mut c = elem("login", "zkproofport");
    c.asserts[0].path.kinds[0] = 3;
    ok_loc::<T, _, A>(GH_ORGS, GH_ORGS_C, c, eloc(GH_ORGS_ZKP_K, GH_ORGS_ZKP_V, GH_ORGS_ZKP_L));
}

#[capacities(1, "claim hash mismatch")]
fn test_claim_hash_covers_the_path<let A: u32>() {
    let c = elem("login", "zkproofport");
    let mut other = c;
    other.asserts[0].path = p1("login");
    run_loc::<T, _, A>(
        GH_ORGS,
        GH_ORGS.as_bytes().len(),
        true,
        GH_ORGS_C,
        BLINDER,
        c,
        eloc(GH_ORGS_ZKP_K, GH_ORGS_ZKP_V, GH_ORGS_ZKP_L),
        claim_hash_of(other, T),
        nullifier_of(c),
    );
}

// ---- Malformed bodies: guards that valid JSON never reaches -------------

use crate::vectors_ws::{
    BAD_ARRELEM, BAD_ARRELEM_C, BAD_ARRELEM_LOGIN_K, BAD_ARRELEM_LOGIN_L, BAD_ARRELEM_LOGIN_V,
    BAD_COMMA, BAD_COMMA_C, BAD_COMMA_EMAIL_K, BAD_COMMA_EMAIL_L, BAD_COMMA_EMAIL_V, BAD_COMMA_SUB_K,
    BAD_COMMA_SUB_V, BAD_NOCOLON, BAD_NOCOLON_C, BAD_NOCOLON_EMAIL_K, BAD_NOCOLON_EMAIL_L,
    BAD_NOCOLON_EMAIL_V, BAD_NOCOLON_SUB_K, BAD_NOCOLON_SUB_V,
};

#[capacities(1, "no colon after key")]
fn test_bad_key_without_colon_fails<let A: u32>() {
    // {"sub": "...", "email" "x@gmail.com"}: whitespace only, no colon.
    ok_loc::<T, _, A>(
        BAD_NOCOLON,
        BAD_NOCOLON_C,
        google("email", KIND_STRING, OP_ENDS_WITH, "@gmail.com"),
        gsub(BAD_NOCOLON_SUB_K, BAD_NOCOLON_SUB_V, BAD_NOCOLON_EMAIL_K, BAD_NOCOLON_EMAIL_V, BAD_NOCOLON_EMAIL_L),
    );
}

#[capacities(1, "no colon after key")]
fn test_bad_other_byte_beside_colon_fails<let A: u32>() {
    // {"sub": "...", "email": , "x@gmail.com"}: one colon, plus a comma.
    ok_loc::<T, _, A>(
        BAD_COMMA,
        BAD_COMMA_C,
        google("email", KIND_STRING, OP_ENDS_WITH, "@gmail.com"),
        gsub(BAD_COMMA_SUB_K, BAD_COMMA_SUB_V, BAD_COMMA_EMAIL_K, BAD_COMMA_EMAIL_V, BAD_COMMA_EMAIL_L),
    );
}

#[capacities(1, "key follows a value that is not an object")]
fn test_bad_member_inside_array_element_array_fails<let A: u32>() {
    // [["login":"zkproofport"]]: the element holding the key is an array.
    ok_loc::<T, _, A>(
        BAD_ARRELEM,
        BAD_ARRELEM_C,
        elem("login", "zkproofport"),
        eloc(BAD_ARRELEM_LOGIN_K, BAD_ARRELEM_LOGIN_V, BAD_ARRELEM_LOGIN_L),
    );
}

#[capacities(1, "date must be YYYY-MM-DD or YYYY-MM-DDT...")]
fn test_date_with_other_suffix_fails<let A: u32>() {
    ok_loc::<T, _, A>(
        GH_USER,
        GH_USER_C,
        github("created_at", KIND_STRING, OP_DATE_BEFORE, "2020-01-01Z"),
        ghloc(GH_USER_CREATED_K, GH_USER_CREATED_V, GH_USER_CREATED_L),
    );
}

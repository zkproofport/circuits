//! Inputs for the circuits' OPRF nullifier (`circuits/oprf-nullifier-libs`),
//! computed with TACEO's crates (`taceo-oprf-core` 0.6.3, `taceo-poseidon2`
//! 0.3.1 -- the versions `proofport-oprf` and TaceoLabs/oprf-testnet v0.4.0
//! use) and a key given on the command line. Nothing here talks to a network;
//! the node's answer is computed locally with that key.
//!
//!   oprf-fixture values --address 0x<20 bytes> --domain 0x.. --scope 0x.. --key 0x.. --beta 0x.. --seed <u64>
//!       One honest OPRF evaluation, as JSON: the public values the circuit
//!       publishes (oprf_key_hash, domain, scope, nullifier) and its private
//!       inputs (public key, beta, Chaum-Pedersen e/s, unblinded response).
//!       Checked with taceo-oprf-core's own client verification before it is
//!       printed.
//!
//!   oprf-fixture noir-vectors --address .. --domain .. --scope .. --key .. --other-key .. --beta .. --seed <u64>
//!       A Noir module of constants for the library's tests: the honest
//!       values, plus the dishonest answers the tests need (another key's
//!       answer, a proof from one key over another key's answer, ...).
//!
//! `--seed` fixes the Chaum-Pedersen nonce so a fixture regenerates byte for
//! byte. A real client never chooses it; the node does, at random.
//!
//! Every field value is 0x-prefixed big-endian hex and must be below its
//! modulus: a value at or above it is refused, never reduced, because two
//! encodings of one value would be two requests that mean the same thing.

use ark_babyjubjub::{EdwardsAffine as Affine, EdwardsProjective, Fq, Fr};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, PrimeField, Zero};
use eyre::{Result, bail, eyre};
use num_bigint::BigUint;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use taceo_oprf_core::{
    dlog_equality::DLogEqualityProof,
    oprf::{BlindedOprfResponse, BlindingFactor, client},
};

/// TACEO's domain separators for this integration (2026-11-17), the ASCII
/// string read as a big-endian integer. Must equal the globals of the same
/// name in circuits/oprf-nullifier-libs/src/lib.nr.
const DS_QUERY: &[u8] = b"TACEO_OPRF_zkProofport_query";
const DS_OUT: &[u8] = b"TACEO_OPRF_zkProofport_out";
const DS_KEY: &[u8] = b"TACEO_OPRF_bjj_key";

fn ds(bytes: &[u8]) -> Fq {
    Fq::from_be_bytes_mod_order(bytes)
}

fn hex32(b: &[u8]) -> String {
    let mut s = String::from("0x");
    for _ in b.len()..32 {
        s.push_str("00");
    }
    for byte in b {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

fn fq_hex(x: &Fq) -> String {
    hex32(&x.into_bigint().to_bytes_be())
}

fn fr_hex(x: &Fr) -> String {
    hex32(&x.into_bigint().to_bytes_be())
}

fn parse_below(s: &str, modulus: BigUint, what: &str) -> Result<BigUint> {
    let t = s.strip_prefix("0x").ok_or_else(|| eyre!("{what}: expected 0x-prefixed hex, got '{s}'"))?;
    let v = BigUint::parse_bytes(t.as_bytes(), 16).ok_or_else(|| eyre!("{what}: not hex: '{s}'"))?;
    if v >= modulus {
        bail!("{what}: {s} is not below the field modulus");
    }
    Ok(v)
}

fn parse_fq(s: &str, what: &str) -> Result<Fq> {
    let v = parse_below(s, Fq::MODULUS.into(), what)?;
    Ok(Fq::from_be_bytes_mod_order(&v.to_bytes_be()))
}

fn parse_fr(s: &str, what: &str) -> Result<Fr> {
    let v = parse_below(s, Fr::MODULUS.into(), what)?;
    Ok(Fr::from_be_bytes_mod_order(&v.to_bytes_be()))
}

/// The 20 address bytes read big-endian -- what the circuit's address_field does.
fn parse_address(s: &str) -> Result<Fq> {
    let t = s.strip_prefix("0x").ok_or_else(|| eyre!("address must be 0x-prefixed"))?;
    if t.len() != 40 {
        bail!("address must be 20 bytes, got '{s}'");
    }
    let v = BigUint::parse_bytes(t.as_bytes(), 16).ok_or_else(|| eyre!("address is not hex: '{s}'"))?;
    Ok(Fq::from_be_bytes_mod_order(&v.to_bytes_be()))
}

fn query(address: Fq, domain: Fq, scope: Fq) -> Fq {
    poseidon2::bn254::t4::permutation(&[ds(DS_QUERY), address, domain, scope])[1]
}

fn key_hash(pk: &Affine) -> Fq {
    poseidon2::bn254::t3::permutation(&[ds(DS_KEY), pk.x, pk.y])[1]
}

fn public_key(k: &Fr) -> Affine {
    (EdwardsProjective::generator() * k).into_affine()
}

/// What the node and the client produce for one request.
struct Evaluation {
    query: Fq,
    pk: Affine,
    blinded: Affine,
    response_blinded: Affine,
    proof: DLogEqualityProof,
    response: Affine,
    nullifier: Fq,
}

/// The node's answer to `query` under key `k`, blinded with `beta`, and the
/// client's finalize step. Refuses to return values taceo-oprf-core's own
/// client check rejects.
fn evaluate(q: Fq, k: Fr, beta: Fr, rng: &mut ChaCha20Rng) -> Result<Evaluation> {
    if k.is_zero() {
        bail!("key must not be zero");
    }
    let factor = BlindingFactor::from_scalar(beta).map_err(|e| eyre!("beta: {e}"))?;
    let blinded = client::blind_query(q, factor.clone()).blinded_query();
    let response_blinded = (blinded * k).into_affine();
    let proof = DLogEqualityProof::proof(blinded, k, rng);
    let pk = public_key(&k);
    let prepared = factor.prepare();
    let response = BlindedOprfResponse::new(response_blinded);
    let nullifier = client::finalize_query_and_verify_proof(pk, q, &response, &proof, &prepared, ds(DS_OUT))
        .map_err(|_| eyre!("taceo-oprf-core refuses the evaluation it just made"))?;
    Ok(Evaluation {
        query: q,
        pk,
        blinded,
        response_blinded,
        proof,
        response: response.unblind_response(&prepared),
        nullifier,
    })
}

fn arg(args: &[String], name: &str) -> Result<String> {
    let i = args.iter().position(|a| a == name).ok_or_else(|| eyre!("{name} is required"))?;
    args.get(i + 1).cloned().ok_or_else(|| eyre!("{name} needs a value"))
}

struct Common {
    address: String,
    address_field: Fq,
    domain: Fq,
    scope: Fq,
    key: Fr,
    beta: Fr,
    rng: ChaCha20Rng,
}

fn common(args: &[String]) -> Result<Common> {
    let address = arg(args, "--address")?;
    let seed: u64 = arg(args, "--seed")?.parse().map_err(|e| eyre!("--seed: {e}"))?;
    Ok(Common {
        address_field: parse_address(&address)?,
        address,
        domain: parse_fq(&arg(args, "--domain")?, "domain")?,
        scope: parse_fq(&arg(args, "--scope")?, "scope")?,
        key: parse_fr(&arg(args, "--key")?, "key")?,
        beta: parse_fr(&arg(args, "--beta")?, "beta")?,
        rng: ChaCha20Rng::seed_from_u64(seed),
    })
}

fn values(args: &[String]) -> Result<()> {
    let mut c = common(args)?;
    let e = evaluate(query(c.address_field, c.domain, c.scope), c.key, c.beta, &mut c.rng)?;
    let v = serde_json::json!({
        "address": c.address,
        "address_field": fq_hex(&c.address_field),
        "domain": fq_hex(&c.domain),
        "scope": fq_hex(&c.scope),
        "query": fq_hex(&e.query),
        "oprf_key_hash": fq_hex(&key_hash(&e.pk)),
        "nullifier": fq_hex(&e.nullifier),
        "oprf_public_key_x": fq_hex(&e.pk.x),
        "oprf_public_key_y": fq_hex(&e.pk.y),
        "oprf_beta": fr_hex(&c.beta),
        "oprf_dlog_e": fq_hex(&e.proof.e()),
        "oprf_dlog_s": fr_hex(&e.proof.s()),
        "oprf_response_x": fq_hex(&e.response.x),
        "oprf_response_y": fq_hex(&e.response.y),
        "blinded_x": fq_hex(&e.blinded.x),
        "blinded_y": fq_hex(&e.blinded.y),
        "response_blinded_x": fq_hex(&e.response_blinded.x),
        "response_blinded_y": fq_hex(&e.response_blinded.y),
    });
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

fn noir_vectors(args: &[String]) -> Result<()> {
    let mut c = common(args)?;
    let other_key = parse_fr(&arg(args, "--other-key")?, "other key")?;
    let q = query(c.address_field, c.domain, c.scope);
    let honest = evaluate(q, c.key, c.beta, &mut c.rng)?;
    // The other key's honest answer to the same blinded query, with its own
    // proof: consistent under the other key, wrong under the pinned one.
    let other = evaluate(q, other_key, c.beta, &mut c.rng)?;
    // Another wallet's honest answer under the pinned key.
    let other_address = c.address_field + Fq::from(1u64);
    let other_wallet = evaluate(query(other_address, c.domain, c.scope), c.key, c.beta, &mut c.rng)?;
    // The query with domain and scope swapped, answered honestly.
    let swapped = evaluate(query(c.address_field, c.scope, c.domain), c.key, c.beta, &mut c.rng)?;

    let mut out = String::new();
    out.push_str("// GENERATED by scripts/oprf-nullifier/make-test-vectors.sh -- do not edit.\n");
    out.push_str("// TACEO's crates (taceo-oprf-core 0.6.3, taceo-poseidon2 0.3.1) and a local\n");
    out.push_str("// test key; the Chaum-Pedersen nonces come from a fixed seed.\n\n");
    let mut g = |name: &str, v: String| out.push_str(&format!("pub(crate) global {name}: Field = {v};\n"));
    g("ADDRESS", fq_hex(&c.address_field));
    g("DOMAIN", fq_hex(&c.domain));
    g("SCOPE", fq_hex(&c.scope));
    g("QUERY", fq_hex(&q));
    g("BETA", fr_hex(&c.beta));
    g("PK_X", fq_hex(&honest.pk.x));
    g("PK_Y", fq_hex(&honest.pk.y));
    g("KEY_HASH", fq_hex(&key_hash(&honest.pk)));
    g("DLOG_E", fq_hex(&honest.proof.e()));
    g("DLOG_S", fr_hex(&honest.proof.s()));
    g("RESP_X", fq_hex(&honest.response.x));
    g("RESP_Y", fq_hex(&honest.response.y));
    g("BLINDED_X", fq_hex(&honest.blinded.x));
    g("BLINDED_Y", fq_hex(&honest.blinded.y));
    g("NULLIFIER", fq_hex(&honest.nullifier));
    g("OTHER_PK_X", fq_hex(&other.pk.x));
    g("OTHER_PK_Y", fq_hex(&other.pk.y));
    g("OTHER_KEY_HASH", fq_hex(&key_hash(&other.pk)));
    g("OTHER_DLOG_E", fq_hex(&other.proof.e()));
    g("OTHER_DLOG_S", fr_hex(&other.proof.s()));
    g("OTHER_RESP_X", fq_hex(&other.response.x));
    g("OTHER_RESP_Y", fq_hex(&other.response.y));
    g("OTHER_NULLIFIER", fq_hex(&other.nullifier));
    g("OTHER_WALLET_ADDRESS", fq_hex(&other_address));
    g("OTHER_WALLET_DLOG_E", fq_hex(&other_wallet.proof.e()));
    g("OTHER_WALLET_DLOG_S", fr_hex(&other_wallet.proof.s()));
    g("OTHER_WALLET_RESP_X", fq_hex(&other_wallet.response.x));
    g("OTHER_WALLET_RESP_Y", fq_hex(&other_wallet.response.y));
    g("OTHER_WALLET_NULLIFIER", fq_hex(&other_wallet.nullifier));
    g("SWAPPED_DLOG_E", fq_hex(&swapped.proof.e()));
    g("SWAPPED_DLOG_S", fr_hex(&swapped.proof.s()));
    g("SWAPPED_RESP_X", fq_hex(&swapped.response.x));
    g("SWAPPED_RESP_Y", fq_hex(&swapped.response.y));
    g("SWAPPED_NULLIFIER", fq_hex(&swapped.nullifier));
    // Moduli, for the boundary tests.
    g("BJJ_SCALAR_ORDER", hex32(&Fr::MODULUS.to_bytes_be()));
    print!("{out}");
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().ok_or_else(|| eyre!("usage: oprf-fixture values|noir-vectors ..."))?;
    match cmd.as_str() {
        "values" => values(&args),
        "noir-vectors" => noir_vectors(&args),
        other => bail!("unknown command '{other}'. Known: values, noir-vectors."),
    }
}

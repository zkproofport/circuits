// PROTOTYPE -- the proof a wallet attaches to an OPRF request (TACEO's SoW,
// 2026-11-17).
//
// The nodes multiply whatever point they are sent by their key. Unchecked,
// anyone could send the encoding of every public KYC address's query and get
// back what each nullifier is built from. So a request carries this proof:
// the blinded point is beta * encode(query) for query =
// Poseidon2(DS_QUERY, address, domain, scope) (oprf-nullifier-libs), and the
// address's key signed the request.
//
// The request is EIP-712 typed data of readable strings -- domain
// EIP712Domain(string name,string version) = ("TACEO:OPRF", "1"), message
// OprfRequest(string statement,string domainName,string scopeName,uint256 deadline)
// with statement "TACEO:OPRF Request" (TACEO's proposal, 2026-11-17). The
// NODES compute its digest in plain (proofport-oprf/src/auth.rs), reduce each
// name to a field (keccak256(utf8(name)) mod p), and pass digest, domain and
// scope in as public inputs. The circuit does no hashing for the signature:
// it checks the secp256k1 signature on that digest and that the key is the
// address's. The nodes check the names, the deadline (and, in the SoW, an
// optional nonce). Because the node computes the digest and the fields from
// the strings it reads, the prover cannot choose the hash the signature is
// checked against, nor a domain or scope other than the signed names'.
//
// Public inputs, in bb's order: digest (32 fields, one per byte), domain,
// scope, then the returned blinded point (x, y).
//
// Gadgets: TaceoLabs/oprf-nr v2.0.0 (deps/oprf-nr).

use babyjubjub::BabyJubJubPointInSubgroup;
use coinbase_libs::ethereum::derive_address_from_pubkey;
use oprf::blinded_query::blinded_query;
use oprf_nullifier_libs::{address_field, oprf_query};

fn main(
    digest: pub [u8; 32],
    domain: pub Field,
    scope: pub Field,
    user_pubkey_x: [u8; 32],
    user_pubkey_y: [u8; 32],
    user_signature: [u8; 64],
    beta: Field,
) -> pub BabyJubJubPointInSubgroup {
    // Recovery, as the SoW words it: the signature verifies under this key
    // and the key's address is the one the query is built from.
    assert(
        std::ecdsa_secp256k1::verify_signature(user_pubkey_x, user_pubkey_y, user_signature, digest),
        "Invalid signature on the OPRF request",
    );
    let address = address_field(derive_address_from_pubkey(user_pubkey_x, user_pubkey_y));
    blinded_query(beta, oprf_query(address, domain, scope))
}

mod tests {
    use super::main;

    // Anvil's well-known account 0 (0xf39f...2266), the wallet TACEO's
    // oprf-testnet circuits test with, signing (ethers signTypedData,
    // proofport-oprf/scripts/sign-request.js) the EIP-712 OprfRequest with
    // domainName "zkproofport.app", scopeName "request-auth-test 요청 🔐" and
    // deadline 2000000000. DIGEST is ethers' TypedDataEncoder.hash of it
    // (0x8318...09cc), and equals proofport-oprf's `oprf digest` (Rust,
    // auth.rs) for the same names. DOMAIN and SCOPE are the names reduced
    // (keccak256(utf8(name)) mod p), by Rust and JS alike.
    global PUB_X: [u8; 32] = [
        131, 24, 83, 91, 84, 16, 93, 74, 122, 174, 96, 192, 143, 196, 95, 150, 135, 24, 27, 79,
        223, 198, 37, 189, 26, 117, 63, 167, 57, 127, 237, 117,
    ];
    global PUB_Y: [u8; 32] = [
        53, 71, 241, 28, 168, 105, 102, 70, 242, 243, 172, 176, 142, 49, 1, 106, 250, 194, 62, 99,
        12, 93, 17, 245, 159, 97, 254, 245, 123, 13, 42, 165,
    ];
    global DIGEST: [u8; 32] = [
        131, 24, 171, 223, 209, 191, 16, 150, 249, 188, 148, 147, 207, 124, 186, 155, 119, 101, 152,
        106, 238, 112, 40, 249, 90, 122, 161, 208, 7, 83, 9, 204,
    ];
    global SIGNATURE: [u8; 64] = [
        143, 126, 198, 42, 54, 93, 11, 83, 247, 145, 192, 153, 226, 180, 25, 65, 3, 7, 193, 52, 112,
        40, 37, 255, 3, 196, 62, 207, 139, 25, 182, 110, 89, 107, 209, 190, 110, 90, 92, 172, 220,
        207, 222, 4, 188, 249, 124, 108, 61, 208, 135, 249, 216, 11, 86, 241, 2, 46, 159, 45, 36,
        46, 60, 198,
    ];
    global BETA: Field =
        1498760273557913456370459222027449040163634869948415528344868600761947487523;
    global DOMAIN: Field = 0x18710bf90bfc93f0c5e493223ae90dd38acb94ecce696da5005658255fed19cc;
    global SCOPE: Field = 0x134603a235af884fa55819d0b300afc465e2581e5a8a655a74c43b49ac31d378;
    // proofport-oprf `oprf blind` (taceo-poseidon2 + taceo-oprf-core) for this
    // wallet, domain, scope and beta.
    global QUERY: Field = 0x1aefdadbcd2c8cd763cf215dfc55df3207f5449a003fca3d572b0e50e5809175;
    global QUERY_POINT_X: Field = 0x290ecff515315e35c5e58c5d9767246e993d1d6691a36fd2bc46d5074f364424;
    global QUERY_POINT_Y: Field = 0x16e681f87c421b80483befc4fa08ffaaa7452391983adb70513c5907144b5c43;

    #[test]
    fn blinds_the_query_of_the_signing_wallet() {
        // Cross-implementation: the Noir query and blinded point equal the
        // Rust ones for the same inputs.
        let got = main(DIGEST, DOMAIN, SCOPE, PUB_X, PUB_Y, SIGNATURE, BETA);
        let query = oprf_nullifier_libs::oprf_query(0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266, DOMAIN, SCOPE);
        assert(query == QUERY, "query differs from proofport-oprf's");
        assert(
            (got.x() == QUERY_POINT_X) & (got.y() == QUERY_POINT_Y),
            "blinded point differs from proofport-oprf's",
        );
    }

    #[test(should_fail_with = "Invalid signature on the OPRF request")]
    fn another_digest_is_refused() {
        let mut d = DIGEST;
        d[0] += 1;
        let _ = main(d, DOMAIN, SCOPE, PUB_X, PUB_Y, SIGNATURE, BETA);
    }

    #[test(should_fail_with = "Invalid signature on the OPRF request")]
    fn a_tampered_signature_is_refused() {
        let mut s = SIGNATURE;
        s[40] += 1;
        let _ = main(DIGEST, DOMAIN, SCOPE, PUB_X, PUB_Y, s, BETA);
    }

    #[test]
    fn another_scope_gives_another_point() {
        // The signature is on the digest only; domain and scope reach the
        // query, and the NODE ties them to the digest it computed.
        let got = main(DIGEST, DOMAIN, SCOPE + 1, PUB_X, PUB_Y, SIGNATURE, BETA);
        assert(got.x() != QUERY_POINT_X);
    }

    #[test(should_fail_with = "Beta cannot be zero")]
    fn zero_beta_is_refused() {
        let _ = main(DIGEST, DOMAIN, SCOPE, PUB_X, PUB_Y, SIGNATURE, 0);
    }
}

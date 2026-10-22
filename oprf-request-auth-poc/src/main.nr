// PROTOTYPE -- what the app hands the OPRF service with a request.
//
// The service multiplies whatever point it is sent by its key. Unchecked,
// anyone could send the encoding of every public KYC address and get back the
// value each address's nullifier is built from -- the same enumeration the
// OPRF exists to stop. So a request carries this proof: the blinded point is
// the encoding of an address whose key signed `challenge`. Only the wallet's
// owner can make it. The service learns neither the address nor beta.
//
// Public outputs, in bb's public-input order: challenge (32 fields), then the
// blinded point (x, y). The service checks the point it received equals them.

use dep::std;
use babyjubjub::BabyJubJubPoint;
use oprf::blinded_query::blinded_query;
use dep::coinbase_libs::ethereum::{create_eth_signed_message_hash, derive_address_from_pubkey};

pub fn address_field(address: [u8; 20]) -> Field {
    let mut acc: Field = 0;
    for i in 0..20 {
        acc = acc * 256 + address[i] as Field;
    }
    acc
}

fn main(
    challenge: pub [u8; 32],
    user_pubkey_x: [u8; 32],
    user_pubkey_y: [u8; 32],
    user_signature: [u8; 64],
    beta: Field,
) -> pub BabyJubJubPoint {
    let address = derive_address_from_pubkey(user_pubkey_x, user_pubkey_y);
    let digest = create_eth_signed_message_hash(challenge);
    assert(
        std::ecdsa_secp256k1::verify_signature(user_pubkey_x, user_pubkey_y, user_signature, digest),
        "Invalid signature on the OPRF challenge",
    );
    blinded_query(beta, address_field(address))
}

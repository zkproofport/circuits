// Probe: the factory chain alone (RSA root as witnesses). Not a circuit anyone proves.
use android_key_attestation::{android_factory_signing_key, FactoryChain};
fn main(c: FactoryChain, m: [u128; 35], r: [u128; 35], d: [u8; 32]) -> pub [u8; 32] {
    let (x, _) = android_factory_signing_key(c, m, r, "com.masselabs.zkproofport".as_bytes(), d);
    x
}

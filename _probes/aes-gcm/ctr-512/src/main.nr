fn main(key: [u8; 32], iv: [u8; 12], ct: [u8; 512]) -> pub [Field; 17] {
    let pt = aes::ctr_decrypt(aes::expand_key(key), iv, ct);
    aes::pack(pt)
}

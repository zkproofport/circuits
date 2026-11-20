fn main(key: [u8; 32], iv: [u8; 12], ct: [u8; 1024]) -> pub [Field; 34] {
    let pt = aes::ctr_decrypt(aes::expand_key(key), iv, ct);
    aes::pack(pt)
}

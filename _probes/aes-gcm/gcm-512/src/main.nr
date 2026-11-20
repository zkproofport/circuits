fn main(key: [u8; 32], iv: [u8; 12], ct: [u8; 512], tag: [u8; 16]) -> pub [Field; 17] {
    let pt = aes::gcm_decrypt(key, iv, ct, tag);
    aes::pack(pt)
}

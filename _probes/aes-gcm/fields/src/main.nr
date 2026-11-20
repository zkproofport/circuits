// Three fields of an identity-verification result, sizes fixed for measuring:
// birthday 8 bytes (YYYYMMDD), name 18 bytes (six Korean syllables in UTF-8),
// DI 88 bytes (the longer of the two lengths quoted for CI/DI).
fn main(
    key: [u8; 32], iv: [u8; 12],
    birthday: [u8; 8], birthday_tag: [u8; 16],
    name: [u8; 18], name_tag: [u8; 16],
    di: [u8; 88], di_tag: [u8; 16],
) -> pub [Field; 4] {
    let s = aes::session(key, iv);
    let ks: [u8; 96] = aes::keystream::<6>(s);
    let b = aes::open_field(s, ks, birthday, birthday_tag);
    let n = aes::open_field(s, ks, name, name_tag);
    let d = aes::open_field(s, ks, di, di_tag);
    let packed_d: [Field; 3] = aes::pack(d);
    let mut tail = [0 as u8; 26];
    for i in 0..8 { tail[i] = b[i]; }
    for i in 0..18 { tail[8 + i] = n[i]; }
    let packed_t: [Field; 1] = aes::pack(tail);
    [packed_d[0], packed_d[1], packed_d[2], packed_t[0]]
}

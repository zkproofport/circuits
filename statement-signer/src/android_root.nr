// Google's Key Attestation CA1 root public key, X || Y (P-384): the only
// Google key the Android signer pins. Every Android statement must come from
// a Remote Key Provisioning chain under it (../android-key-attestation).
//
//   subject   CN=Key Attestation CA1, OU=Android, O=Google LLC, C=US
//   validity  2025-07-17 to 2035-07-15 22:32:18 UTC
//   SHA-256 of the certificate 6D:9D:B4:CE:6C:5C:0B:29:31:66:D0:89:86:E0:57:74:
//             A8:77:6C:EB:52:5D:9E:43:29:52:0D:E1:2B:A4:BC:C0
//   source    developer.android.com/privacy-and-security/security-key-attestation
//             "Root certificates" (read 2026-10-28): "will begin signing
//             attestation certificate chains on February 1, 2026"
//
// android-key-attestation's tests verify real Google chains (Pixel, Android
// 16) against these bytes. When Google issues another root, every circuit
// using this file needs a release (new vk, verifier redeploy) -- the same
// price as Apple's intermediate in apple_ca.nr, paid less often (2035).
//
// The acceptance runs' synthetic-anchors copy
// (scripts/statement-signer/make-synthetic-anchors.sh) replaces the line
// below with a synthetic root whose private key the fixture generators hold.

pub global GOOGLE_KEY_ATTESTATION_ROOT: [u8; 96] = [
    0x23, 0xda, 0x23, 0x71, 0x4e, 0xdf, 0x3e, 0x5b, 0x05, 0x0a, 0x3c, 0x72, 0xe8, 0x84, 0x6a, 0xce,
    0x07, 0x8e, 0xa0, 0xad, 0x1b, 0xf9, 0x8b, 0x15, 0xf4, 0x53, 0xd0, 0xcb, 0x08, 0xb2, 0xc3, 0xc1,
    0x10, 0x45, 0x39, 0x09, 0xf6, 0xed, 0xea, 0xc1, 0xf9, 0xc8, 0xe0, 0x31, 0xa8, 0x48, 0xb9, 0x41,
    0xa8, 0x29, 0x53, 0x5c, 0x97, 0xe0, 0x7c, 0x27, 0x19, 0xbe, 0xce, 0xb4, 0x16, 0x29, 0x0d, 0x30,
    0x79, 0xee, 0xe1, 0xf9, 0x11, 0xcc, 0xe6, 0xdf, 0x80, 0x39, 0x14, 0xd8, 0xa3, 0x57, 0x7b, 0x34,
    0xfd, 0xfd, 0x14, 0x3e, 0x5e, 0xf3, 0x6c, 0x97, 0x13, 0xc7, 0xac, 0x70, 0xa8, 0xc2, 0x11, 0xab,
];

// Google's RSA-4096 attestation root (serialNumber f92009e853b6b045), the
// root of factory-provisioned chains (devices launched with Android 12 or
// earlier). One key behind its 2016, 2019 and 2022 certificates (same
// modulus, read 2026-10-28 from developer.android.com's root list), in
// noir-bignum's 35 little-endian 120-bit limbs, with its Barrett parameter
// floor(2^8196 / n) (scripts/android-key-attestation/chain.js rsa4096Params).
// Factory chains are accepted only together with a Play Integrity verdict
// (play_key.nr, verify_statement_android_factory). The synthetic-anchors
// copy replaces both lines with a synthetic RSA root.

pub global GOOGLE_RSA_ROOT_MODULUS_LIMBS: [u128; 35] = [
    0x580d3cdf4fbd08bc5848395260063,
    0xf4d69b6420051fdb93049673e3695,
    0x4725861f093dd0e6f3405da89643ef,
    0xd0a54a6e2f5d9a6fef446832bc6784,
    0x959d653740d97a12f368b13ef66d5,
    0xd31145ebf9e862ad71df6a3bfd245,
    0x7ab545c723ff8c44f8f2d368b9f652,
    0x85015b422ce67b80b88c9b48e13b60,
    0xc1e4df9eaf9ff6a492a77c14838828,
    0xbcd24628a01c2cc03e51f0b3e5b4a,
    0xf359082966bb778b9308942698e74e,
    0x8833b018daa10e451f06a374d50781,
    0x20b135158b6821ceaf309b6eee77f9,
    0xeabaf99a83c8df3e2a322afc672bf1,
    0x123887e06becf567583bf8355a81fe,
    0xec06c94766f3c128239d4f4312fad8,
    0x72c049604bbd2f1345e62c3f8e26db,
    0x4c80927499c0e9bec0b83e3bc1f93c,
    0xe55d370762f0122eef91861b1b0e6c,
    0xa5fe6d3440b556bad1d0a152589c53,
    0xc2f14ad6d03c56ec060899041c1ed1,
    0x7944864604ddb3d8c4f920a19b1656,
    0x27d67fd6f671aa0b815261ad384fa3,
    0xad9eb2a96bbdd7a57c93a91c41fccd,
    0x9c5e3a7790e1b51442793159859811,
    0x4bfe08239daafceb8eb5a8ed2b3acd,
    0x51b6feb2fffd2b6fe4fe5bc6bd9ec3,
    0x9f3201f44197ca1ccd7e762fb2f531,
    0xfbb6fd129378a22a4ca99c452d47a5,
    0x639517dd9c92e6374a53cbfe258f8f,
    0x35744aa55e77f6b6ac3535ee17c25e,
    0x5fe809fbc72aa9451f743cbd9a6f13,
    0xabef982f32c77f7531030c97524b1b,
    0xc7822bb1a701ec2bb42e8bcc541663,
    0xafb6,
];
pub global GOOGLE_RSA_ROOT_REDC_LIMBS: [u128; 35] = [
    0xfa08e86fdf26ffa3d06366b86c2052,
    0x85e314b3716438fe0598ebf1a5e0f,
    0xb900e119595521c8fc14f3fe046077,
    0x7971e7152f07e0beca6b9a3a90bcb9,
    0x67f73c7b7191ee6322a294c5d845ab,
    0x9a39137d3fd8e3b7a76f6ff6d78531,
    0xb6d7124470aead3d71543eed38e8c8,
    0xb244b969ad81ac1fbe4f00a5535c02,
    0xd6169b5b81191fe1949d4b70531ef1,
    0xbc92835b8914021e5f3b287109d072,
    0x93f06bdd78eda4bf32d5119882f9b8,
    0xbad34eb2742740ec90a1a32b34dc61,
    0x66a8f5663cc2d84df6fdb3004174e3,
    0x5555f131677341bdbda7c515dfc02,
    0x72a739ed7fc0e21c972405ab184d7,
    0x6a59f58629ca8b3bba3d5d54b02421,
    0x9e5678c6ba3e60b377402bab7a86dd,
    0x6eb5ba98e1248a14589cbc36e8520f,
    0x4a578e021f020b50ed58e7a9369c0a,
    0xaa0d089168571c00e751871bd4d8f9,
    0xe4e34e3b29209a0a15659e28727e92,
    0x59ea8ab60c53075cff3e12453046,
    0x14badba472cdd079f26ec14bee8ff9,
    0xa0d8e33870475d15fc958f9d94b07d,
    0xc943ee19cfa0c237c5414397c96aaa,
    0x252957efc965fecce7166b1a679ee2,
    0xbf75e0efe472732ccfa06910b7fc7b,
    0x534999d90eca3b3004ebecdb85e61e,
    0xaab1730a5a35177c5107e47afe3fd3,
    0x8cd4132280507a61cf71d8b615da29,
    0x7f754c84e1ac1b6351d992aa0d3342,
    0x7fd28acac35395527a5e290b1902aa,
    0xfd1a3740a3bbc69bda6924d153c66c,
    0x197c1ad5c62e95fc46ed6e52c33b2c,
    0x174f84,
];

/// rsa_root_hash(GOOGLE_RSA_ROOT_MODULUS_LIMBS, GOOGLE_RSA_ROOT_REDC_LIMBS):
/// what the circuits pin (the limbs are prover inputs; see lib.nr).
pub global GOOGLE_RSA_ROOT_HASH: Field = 0x26e9527b59cfe25f58551f2f14a096144714aa1935271120aef5bc5265d275d4;

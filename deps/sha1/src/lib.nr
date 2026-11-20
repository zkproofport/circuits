mod base4_encoding;
mod base4_decoding;
mod bit_utils;
mod permutation;
mod tables;
mod benchmarks;
pub mod sha1 {
    pub fn digest<let N: u32>(msg: [u8; N]) -> [u8; 20] {
        crate::permutation::digest::<_>(msg)
    }

    pub fn sha1_var<let N: u32>(msg: BoundedVec<u8, N>) -> [u8; 20] {
        crate::permutation::digest_var::<_>(msg)
    }

    // Fuzz testing the sha1 implementation
    #[export]
    fn test_sha1_1(input: BoundedVec<u8, 1>) -> [u8; 20] {
        sha1_var(input)
    }

    #[export]
    fn test_sha1_100(input: BoundedVec<u8, 100>) -> [u8; 20] {
        sha1_var(input)
    }

    #[export]
    fn test_sha1_256(input: BoundedVec<u8, 256>) -> [u8; 20] {
        sha1_var(input)
    }

    #[test]
    fn test_empty_string() {
        let input: [u8; 0] = [];
        let result = digest(input);

        let expected: [u8; 20] = [
            0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60,
            0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09,
        ];

        println(f"result {result}");
        println(f"expected {expected}");
        assert_eq(result, expected);
    }

    #[test]
    fn test_abc() {
        let input = "abc".as_bytes();
        let result = digest(input);
        let result_var = sha1_var(BoundedVec::<u8, 256>::from_array(input));

        let expected: [u8; 20] = [
            0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
            0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
        ];

        println(f"result {result}");
        println(f"expected {expected}");
        assert_eq(result, expected);
        assert_eq(result_var, expected);
    }

    #[test]
    fn test_448_bit_msg() {
        let input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes();
        let result = digest(input);
        let result_var = sha1_var(BoundedVec::<u8, 256>::from_array(input));

        let expected: [u8; 20] = [
            0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e, 0xba, 0xae, 0x4a, 0xa1, 0xf9, 0x51,
            0x29, 0xe5, 0xe5, 0x46, 0x70, 0xf1,
        ];

        println(f"result {result}");
        println(f"expected {expected}");
        assert_eq(result, expected);
        assert_eq(result_var, expected);
    }

    #[test]
    fn test_896_bit_msg() {
        let input = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
            .as_bytes();
        let result = digest(input);
        let result_var = sha1_var(BoundedVec::<u8, 256>::from_array(input));

        let expected: [u8; 20] = [
            0xa4, 0x9b, 0x24, 0x46, 0xa0, 0x2c, 0x64, 0x5b, 0xf4, 0x19, 0xf9, 0x95, 0xb6, 0x70,
            0x91, 0x25, 0x3a, 0x04, 0xa2, 0x59,
        ];

        assert_eq(result, expected);
        assert_eq(result_var, expected);
    }

}

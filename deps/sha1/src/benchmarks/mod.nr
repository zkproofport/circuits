use crate::permutation::digest;

// cost of 10 hashes = 158,945
// cost of 1 hash = 29,315
// incremental hash cost ~ 15k
#[export]
fn bench_digest(input: [u8; 64]) {
    let result = digest::<_>(input);

    let expected: [u8; 20] = [
        0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x07, 0xd6, 0x20, 0xe4, 0x05,
        0x0b, 0x57, 0x15, 0xdc, 0x83,
    ];

    println(f"result {result}");
    println(f"expected {expected}");
    assert_eq(result, expected);
}

#[export]
fn bench_digest_ten(input: [[u8; 64]; 10]) {
    for i in 0..10 {
        let result = digest::<_>(input[i]);

        let expected: [u8; 20] = [
            0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x07, 0xd6, 0x20, 0xe4,
            0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83,
        ];

        println(f"result {result}");
        println(f"expected {expected}");
        assert_eq(result, expected);
    }
}

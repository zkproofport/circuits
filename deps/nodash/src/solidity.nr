use crate::ArrayExtensions;

pub global SELECTOR_LENGTH: u32 = 4;

/// Encodes a function selector and its arguments into a byte array.
///
/// ## Arguments
///
/// * `selector` - The function selector to encode.
/// * `args` - The arguments to encode.
///
/// ## Returns
///
/// A byte array containing the function selector and its arguments.
///
/// ## Example
///
/// ```noir
/// let selector: u32 = 0xa9059cbb; // transfer(address,uint256)
/// let args: [Field; 2] = [
///     0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045, // address
///     123, // uint256
/// ];
/// let encoded = encode_with_selector(selector, args);
/// ```
pub fn encode_with_selector<let N: u32>(
    selector: u32,
    args: [Field; N],
) -> [u8; SELECTOR_LENGTH + N * 32] {
    let selector_bytes: [u8; SELECTOR_LENGTH] = (selector as Field).to_be_bytes();
    encode_with_selector_bytes(selector_bytes, args)
}

pub fn encode_with_selector_bytes<let N: u32>(
    selector: [u8; SELECTOR_LENGTH],
    args: [Field; N],
) -> [u8; SELECTOR_LENGTH + N * 32] {
    let mut result = [0; SELECTOR_LENGTH + N * 32];

    for i in 0..SELECTOR_LENGTH {
        result[i] = selector[i];
    }

    for i in 0..N {
        let bytes: [u8; 32] = args[i].to_be_bytes();
        for j in 0..32 {
            result[SELECTOR_LENGTH + i * 32 + j] = bytes[j];
        }
    }

    result
}

pub fn to_selector<let N: u32>(signature: str<N>) -> [u8; SELECTOR_LENGTH] {
    crate::keccak256(signature.as_bytes()).slice::<SELECTOR_LENGTH>(0)
}

mod tests {
    use crate::solidity::{encode_with_selector, encode_with_selector_bytes, to_selector};

    #[test]
    fn test_simple_selector() {
        let selector: u32 = 0xa9059cbb; // transfer(address,uint256)
        let args: [Field; 2] = [
            0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045, // address
            123, // uint256
        ];
        let encoded = encode_with_selector(selector, args);
        let expected: [u8; 68] = [
            169, 5, 156, 187, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 216, 218, 107, 242, 105, 100, 175,
            157, 126, 237, 158, 3, 229, 52, 21, 211, 122, 169, 96, 69, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 123,
        ];
        assert(encoded == expected);
    }

    #[test]
    fn test_simple_signature() {
        let args: [Field; 2] = [
            0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045, // address
            123, // uint256
        ];

        let encoded =
            encode_with_selector_bytes(comptime { to_selector("transfer(address,uint256)") }, args);
        let expected: [u8; 68] = [
            169, 5, 156, 187, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 216, 218, 107, 242, 105, 100, 175,
            157, 126, 237, 158, 3, 229, 52, 21, 211, 122, 169, 96, 69, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 123,
        ];
        assert(encoded == expected);
    }

    #[test]
    fn test_deposit() {
        let result = encode_with_selector(
            // FunctionSelector::from_signature("deposit_private(bytes32,address[2],uint256[2])"),
            0x86d09dae,
            [
                0x1a7097a0f09457b0b0496684b2ed6723a262da3a1b061b598ee92ce3376cb302,
                0x610178dA211FEF7D417bC0e6FeD39F05609AD788,
                0xB7f8BC63BbcaD18155201308C8f3540b07f84F5e,
                333,
                64,
            ],
        );
        let expected = [
            134, 208, 157, 174, 26, 112, 151, 160, 240, 148, 87, 176, 176, 73, 102, 132, 178, 237,
            103, 35, 162, 98, 218, 58, 27, 6, 27, 89, 142, 233, 44, 227, 55, 108, 179, 2, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 97, 1, 120, 218, 33, 31, 239, 125, 65, 123, 192, 230, 254,
            211, 159, 5, 96, 154, 215, 136, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 183, 248, 188, 99,
            187, 202, 209, 129, 85, 32, 19, 8, 200, 243, 84, 11, 7, 248, 79, 94, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 77, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64,
        ];
        assert(result == expected);
    }
}

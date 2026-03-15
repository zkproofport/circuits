pub trait TryFrom<T> {
    /// Convert or fail.
    fn try_from(input: T) -> Self;
}

impl TryFrom<Field> for u8 {
    fn try_from(input: Field) -> Self {
        input.assert_max_bit_size::<8>();
        input as u8
    }
}

impl TryFrom<Field> for u16 {
    fn try_from(input: Field) -> Self {
        input.assert_max_bit_size::<16>();
        input as u16
    }
}

impl TryFrom<Field> for u32 {
    fn try_from(input: Field) -> Self {
        input.assert_max_bit_size::<32>();
        input as u32
    }
}

impl TryFrom<Field> for u64 {
    fn try_from(input: Field) -> Self {
        input.assert_max_bit_size::<64>();
        input as u64
    }
}

impl TryFrom<Field> for u128 {
    fn try_from(input: Field) -> Self {
        input.assert_max_bit_size::<128>();
        input as u128
    }
}

impl TryFrom<Field> for i8 {
    fn try_from(input: Field) -> Self {
        input.assert_max_bit_size::<8>();
        input as i8
    }
}

impl TryFrom<Field> for i16 {
    fn try_from(input: Field) -> Self {
        input.assert_max_bit_size::<16>();
        input as i16
    }
}

impl TryFrom<Field> for i32 {
    fn try_from(input: Field) -> Self {
        input.assert_max_bit_size::<32>();
        input as i32
    }
}

impl TryFrom<Field> for i64 {
    fn try_from(input: Field) -> Self {
        input.assert_max_bit_size::<64>();
        input as i64
    }
}

mod tests {
    use super::TryFrom;

    #[test]
    fn test_try_from() {
        assert(u8::try_from(123) == 123);
        assert(u128::try_from(123) == 123);
    }

    #[test(should_fail_with = "call to assert_max_bit_size")]
    fn test_try_from_fail() {
        let _ = u8::try_from(256);
    }
}

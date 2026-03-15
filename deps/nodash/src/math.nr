pub(crate) mod sqrt;
pub(crate) mod numeric;

use numeric::Numeric;
use std::{cmp::Eq, ops::{Add, Div, Rem}};

pub fn clamp<T>(x: T, min: T, max: T) -> T
where
    T: Ord,
{
    if (x < min) {
        min
    } else if (x > max) {
        max
    } else {
        x
    }
}

pub fn div_ceil<T>(a: T, b: T) -> T
where
    T: Add + Div + Rem + Eq + Numeric,
{
    let q = a / b;
    if (a % b == T::zero()) {
        q
    } else {
        q + T::one()
    }
}

mod tests {
    use crate::math::{clamp, div_ceil};

    #[test]
    fn test_clamp() {
        // if too small, return min
        assert(clamp(1 as u64, 2 as u64, 3 as u64) == 2 as u64);
        // if too big, return max
        assert(clamp(4 as u64, 1 as u64, 3 as u64) == 3 as u64);
        // if in range, return value
        assert(clamp(2 as u64, 1 as u64, 3 as u64) == 2 as u64);
    }

    #[test]
    fn test_div_ceil() {
        assert(div_ceil(1 as u64, 2) == 1);
        assert(div_ceil(2 as u64, 2) == 1);
        assert(div_ceil(3 as u64, 2) == 2);
        assert(div_ceil(4 as u64, 2) == 2);
        assert(div_ceil(5 as u64, 2) == 3);
        assert(div_ceil(1337 as u64, 19) == 71);
        assert(div_ceil(1337 as u64, 7) == 191);
        assert(div_ceil(10 as u64, 3) == 4);
    }
}

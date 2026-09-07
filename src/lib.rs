//! Verifiable price volatility over Reckle+ trees.
//!
//! This module holds the encoding decisions and the out-of-circuit Map/Reduce.
//! It is deliberately free of Plonky2 types: the same arithmetic has to run
//! both here and inside the circuit, and keeping the reference version plain
//! makes it possible to test one against the other.

pub mod aggregate;
pub mod merkle;
pub mod gadgets;
pub mod circuit_b0;
pub mod circuit_bi;
pub mod reckle_tree;
pub mod baseline;

/// Goldilocks modulus, the field Plonky2 works over.
pub const P: u64 = 0xFFFF_FFFF_0000_0001;

/// Fixed-point scale: prices are stored as `round(usd * SCALE)`.
///
/// Chosen so the worst legal `sumsq` stays under `P` with ~9 bits to spare:
/// `WINDOW * MAX_DEV^2 = 4096 * 2_500_000^2 = 2.56e16 < 1.84e19 = P`.
/// Raising this to `10^4` leaves only 2 bits and is not safe.
pub const SCALE: u64 = 1_000;

/// Largest deviation from `P0` a leaf may carry, encoded. 2500 USD.
pub const MAX_DEV: u64 = 2_500 * SCALE;

/// Bits needed for the shifted range check on `MAX_DEV`.
pub const RANGE_BITS: usize = 23; // 2 * MAX_DEV = 5_000_000 < 2^23

/// Leaves per tree: one block per leaf, ~13.6 h of Ethereum history.
pub const WINDOW: usize = 4096;

/// The Map/Reduce state that travels up the tree.
///
/// Must be a fixed-size commutative monoid: `Reduce` runs pairwise over a
/// binary tree, so the result cannot depend on the grouping. Variance itself
/// is *not* such a value, which is why the circuit emits these three
/// aggregates and leaves the division to the verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Acc {
    pub cnt: u64,
    /// Sum of deviations. Signed; stored as a field element, so a negative
    /// total appears as `P - |x|`. Use [`from_field`] to read it back.
    pub sum: u64,
    /// Sum of squared deviations. Always non-negative and, given the range
    /// check, always below `P` — so it never wraps.
    pub sumsq: u64,
}

/// Lift a signed integer into the field.
pub fn to_field(x: i64) -> u64 {
    if x < 0 {
        P - (x.unsigned_abs())
    } else {
        x as u64
    }
}

/// Read a field element back as signed. Unambiguous while `|x| < P/2`, which
/// the range check guarantees: the worst `|sum|` is about 1e10 against a
/// half-modulus of roughly 9.2e18.
pub fn from_field(x: u64) -> i64 {
    if x > P / 2 {
        -((P - x) as i64)
    } else {
        x as i64
    }
}

/// Convert a USD price to its fixed-point encoding.
pub fn encode(usd: f64) -> u64 {
    (usd * SCALE as f64).round() as u64
}

/// Rejected when a leaf sits outside the permitted band around `P0`.
///
/// This is not a convenience check. Without it a prover can pick deviations
/// large enough to wrap `sumsq` modulo `P` and prove an arbitrary variance;
/// see the `reject_overflow_attack` vector.
#[derive(Debug, PartialEq, Eq)]
pub struct OutOfRange {
    pub deviation: i64,
}

/// Map: one leaf price into `(1, delta, delta^2)`.
pub fn map_leaf(price_enc: u64, p0_enc: u64) -> Result<Acc, OutOfRange> {
    let delta = price_enc as i64 - p0_enc as i64;
    if delta.unsigned_abs() > MAX_DEV {
        return Err(OutOfRange { deviation: delta });
    }
    let sq = (delta * delta) as u64; // <= MAX_DEV^2 = 6.25e12, no overflow
    Ok(Acc { cnt: 1, sum: to_field(delta), sumsq: sq })
}

/// Reduce: component-wise addition in the field.
pub fn reduce(a: Acc, b: Acc) -> Acc {
    let add = |x: u64, y: u64| ((x as u128 + y as u128) % P as u128) as u64;
    Acc {
        cnt: a.cnt + b.cnt,
        sum: add(a.sum, b.sum),
        sumsq: add(a.sumsq, b.sumsq),
    }
}

/// What the verifier computes off-circuit, in USD.
#[derive(Debug, Clone, Copy)]
pub struct Stats {
    pub mean_usd: f64,
    pub variance_usd2: f64,
    pub stddev_usd: f64,
}

/// Derive mean and variance from the three aggregates. Requires `P0` to undo
/// the centring; the variance itself is shift-invariant.
pub fn stats(acc: Acc, p0_enc: u64) -> Stats {
    let n = acc.cnt as f64;
    let sum = from_field(acc.sum) as f64;
    let sumsq = acc.sumsq as f64;
    let mean_enc = p0_enc as f64 + sum / n;
    let var_enc = sumsq / n - (sum / n).powi(2);
    let s = SCALE as f64;
    Stats {
        mean_usd: mean_enc / s,
        variance_usd2: var_enc / (s * s),
        stddev_usd: var_enc.sqrt() / s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_encoding_round_trips() {
        for v in [0i64, 1, -1, MAX_DEV as i64, -(MAX_DEV as i64), 1_234_567] {
            assert_eq!(from_field(to_field(v)), v, "round-trip failed for {v}");
        }
    }

    #[test]
    fn range_check_boundary_is_where_we_claim() {
        let p0 = encode(3000.0);
        assert!(map_leaf(p0 + MAX_DEV, p0).is_ok(), "MAX_DEV must be accepted");
        assert!(map_leaf(p0 + MAX_DEV + 1, p0).is_err(), "MAX_DEV+1 must be rejected");
    }

    #[test]
    fn reduce_is_associative() {
        let (a, b, c) = (
            Acc { cnt: 1, sum: to_field(5), sumsq: 25 },
            Acc { cnt: 1, sum: to_field(-3), sumsq: 9 },
            Acc { cnt: 1, sum: to_field(7), sumsq: 49 },
        );
        assert_eq!(reduce(reduce(a, b), c), reduce(a, reduce(b, c)));
    }

    #[test]
    fn worst_legal_case_fits_under_the_modulus() {
        let worst = WINDOW as u128 * MAX_DEV as u128 * MAX_DEV as u128;
        assert!(worst < P as u128, "sumsq can overflow: retune SCALE or WINDOW");
    }
}

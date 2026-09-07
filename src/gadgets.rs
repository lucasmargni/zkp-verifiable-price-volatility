use plonky2::field::types::Field;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::merkle::F;
use crate::{MAX_DEV, RANGE_BITS};

const D: usize = 2;

/// In-circuit Map for one leaf: `price -> (delta, delta^2)` with the range
/// check that keeps `sumsq` from wrapping.
///
/// Shared by `B0` and the monolithic baseline on purpose. If the two versions
/// drifted apart, the baseline would no longer be proving the same statement
/// and the benchmark comparison would be meaningless.
///
/// The range check is two-sided. `split_le(shifted, RANGE_BITS)` alone only
/// gives `shifted < 2^23 = 8_388_608`, which permits deviations up to
/// `+5_888_607` — more than twice `MAX_DEV`, and asymmetric, since the lower
/// end is pinned at `-MAX_DEV` by `shifted >= 0`. Bounding the complement as
/// well pins the band to exactly `[-MAX_DEV, +MAX_DEV]`: if `shifted` exceeded
/// `2 * MAX_DEV`, the complement would go negative, wrap to roughly `P`, and
/// fail to fit in 23 bits.
pub fn map_leaf_circuit(
    builder: &mut CircuitBuilder<F, D>,
    price: Target,
    p0: Target,
) -> (Target, Target) {
    let max_dev = builder.constant(F::from_canonical_u64(MAX_DEV));
    let two_max_dev = builder.constant(F::from_canonical_u64(2 * MAX_DEV));

    let delta = builder.sub(price, p0);
    let shifted = builder.add(delta, max_dev);

    // shifted < 2^RANGE_BITS  (pins the lower end: delta >= -MAX_DEV)
    let _ = builder.split_le(shifted, RANGE_BITS);
    // 2*MAX_DEV - shifted < 2^RANGE_BITS  (pins the upper end: delta <= MAX_DEV)
    let complement = builder.sub(two_max_dev, shifted);
    let _ = builder.split_le(complement, RANGE_BITS);

    let delta_sq = builder.mul(delta, delta);
    (delta, delta_sq)
}

/// Same Map with the range check removed. **Deliberately unsound.**
///
/// Exists only so the soundness tests can exhibit the attack the check
/// prevents: with no bound on `delta`, a prover picks deviations whose squares
/// wrap modulo `P` and the circuit reports an arbitrarily small variance.
/// Never call this outside tests.
#[doc(hidden)]
pub fn map_leaf_circuit_unchecked(
    builder: &mut CircuitBuilder<F, D>,
    price: Target,
    p0: Target,
) -> (Target, Target) {
    let delta = builder.sub(price, p0);
    let delta_sq = builder.mul(delta, delta);
    (delta, delta_sq)
}
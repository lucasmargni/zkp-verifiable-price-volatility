use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::PoseidonGoldilocksConfig;

use crate::gadgets::{map_leaf_circuit, map_leaf_circuit_unchecked};
use crate::merkle::{F, LeafData};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;

/// Targets used to feed private witness inputs into circuit B0.
pub struct B0Targets {
    pub p0: Target,
    pub left_index: Target,
    pub left_price: Target,
    pub right_index: Target,
    pub right_price: Target,
    pub parent_hash: HashOutTarget,
    pub cnt: Target,
    pub sum: Target,
    pub sumsq: Target,
}

/// Encapsulates the B0 circuit data and its input targets.
pub struct B0Circuit {
    pub data: CircuitData<F, C, D>,
    pub targets: B0Targets,
}

impl B0Circuit {
    /// Builds circuit B0 for processing two leaf nodes without recursion.
    pub fn new() -> Self {
        Self::build(true)
    }

    /// Builds B0 **without** the range check. Deliberately unsound; test-only.
    /// See `gadgets::map_leaf_circuit_unchecked`.
    #[doc(hidden)]
    pub fn new_unchecked() -> Self {
        Self::build(false)
    }

    fn build(range_checked: bool) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // 1. Private witnesses
        let p0 = builder.add_virtual_target();
        let left_index = builder.add_virtual_target();
        let left_price = builder.add_virtual_target();
        let right_index = builder.add_virtual_target();
        let right_price = builder.add_virtual_target();

        // 2-3. In-circuit Map for both leaves, with the two-sided range check
        let map = if range_checked {
            map_leaf_circuit
        } else {
            map_leaf_circuit_unchecked
        };
        let (delta_l, delta_l_sq) = map(&mut builder, left_price, p0);
        let (delta_r, delta_r_sq) = map(&mut builder, right_price, p0);

        // 4. In-circuit base Reduce
        let cnt = builder.constant(F::from_canonical_u64(2));
        let sum = builder.add(delta_l, delta_r);
        let sumsq = builder.add(delta_l_sq, delta_r_sq);

        // 5. In-circuit Poseidon hashes
        let left_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(vec![left_index, left_price]);
        let right_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(vec![right_index, right_price]);

        let mut parent_inputs = Vec::with_capacity(8);
        parent_inputs.extend_from_slice(&left_hash.elements);
        parent_inputs.extend_from_slice(&right_hash.elements);
        let parent_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(parent_inputs);

        // 6. Public inputs: (C, P0, cnt, sum, sumsq)
        builder.register_public_inputs(&parent_hash.elements);
        builder.register_public_input(p0);
        builder.register_public_input(cnt);
        builder.register_public_input(sum);
        builder.register_public_input(sumsq);

        let data = builder.build::<C>();

        let targets = B0Targets {
            p0,
            left_index,
            left_price,
            right_index,
            right_price,
            parent_hash,
            cnt,
            sum,
            sumsq,
        };

        Self { data, targets }
    }

    /// Fills witness targets and generates a proof for circuit B0.
    pub fn prove(
        &self,
        p0: u64,
        left: LeafData,
        right: LeafData,
    ) -> anyhow::Result<plonky2::plonk::proof::ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::new();

        pw.set_target(self.targets.p0, F::from_canonical_u64(p0));
        pw.set_target(self.targets.left_index, F::from_canonical_u64(left.index));
        pw.set_target(self.targets.left_price, F::from_canonical_u64(left.price));
        pw.set_target(self.targets.right_index, F::from_canonical_u64(right.index));
        pw.set_target(self.targets.right_price, F::from_canonical_u64(right.price));

        self.data.prove(pw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::hash_children;
    use crate::{to_field, MAX_DEV};
    use plonky2::field::types::PrimeField64;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::time::Instant;

    /// A leaf is rejected if proving fails, panics during witness generation,
    /// or yields a proof that does not verify. Any of the three counts.
    fn is_rejected(circuit: &B0Circuit, p0: u64, left: LeafData, right: LeafData) -> bool {
        match catch_unwind(AssertUnwindSafe(|| circuit.prove(p0, left, right))) {
            Err(_) => true,
            Ok(Err(_)) => true,
            Ok(Ok(proof)) => circuit.data.verify(proof).is_err(),
        }
    }

    #[test]
    fn test_b0_completeness_and_measure_h() {
        let p0 = 3_000_000u64;
        let left = LeafData::new(0, 3_000_500);
        let right = LeafData::new(1, 2_999_250);

        let circuit = B0Circuit::new();

        let start = Instant::now();
        let proof = circuit.prove(p0, left, right).expect("B0 proving must succeed");
        println!("\n[Benchmark] B0 prove time (leaf level): {:?}", start.elapsed());

        let verify_start = Instant::now();
        circuit.data.verify(proof.clone()).expect("B0 verification must succeed");
        println!("[Benchmark] B0 verify time: {:?}", verify_start.elapsed());

        let expected_parent_hash = hash_children(left.hash(), right.hash());
        let expected_delta_l = left.price as i64 - p0 as i64;
        let expected_delta_r = right.price as i64 - p0 as i64;
        let expected_sum = to_field(expected_delta_l + expected_delta_r);
        let expected_sumsq =
            (expected_delta_l * expected_delta_l + expected_delta_r * expected_delta_r) as u64;

        let pis = &proof.public_inputs;
        assert_eq!(&pis[0..4], &expected_parent_hash.elements);
        assert_eq!(pis[4], F::from_canonical_u64(p0));
        assert_eq!(pis[5], F::from_canonical_u64(2));
        assert_eq!(pis[6], F::from_canonical_u64(expected_sum));
        assert_eq!(pis[7], F::from_canonical_u64(expected_sumsq));
    }

    /// The band must be exactly [-MAX_DEV, +MAX_DEV] and symmetric. A one-sided
    /// `split_le` would pass the first two assertions and fail the last.
    #[test]
    fn test_b0_range_check_band_is_exact_and_symmetric() {
        let p0 = 3_000_000u64;
        let circuit = B0Circuit::new();
        let anchor = LeafData::new(0, p0);

        // Both boundaries accepted.
        for price in [p0 + MAX_DEV, p0 - MAX_DEV] {
            let proof = circuit
                .prove(p0, anchor, LeafData::new(1, price))
                .unwrap_or_else(|_| panic!("deviation of exactly MAX_DEV must be provable ({price})"));
            circuit.data.verify(proof).expect("boundary proof must verify");
        }

        // One tick past either boundary rejected.
        assert!(
            is_rejected(&circuit, p0, anchor, LeafData::new(1, p0 + MAX_DEV + 1)),
            "+MAX_DEV+1 must be rejected"
        );
        assert!(
            is_rejected(&circuit, p0, anchor, LeafData::new(1, p0 - MAX_DEV - 1)),
            "-MAX_DEV-1 must be rejected"
        );
    }

    /// The attack the range check exists to prevent.
    ///
    /// With `delta = 2^32`, the true `delta^2 = 2^64` reduces to `2^32 - 1`
    /// modulo Goldilocks. Two such leaves report `sumsq = 8_589_934_590`
    /// instead of `2^65`, so the verifier reads a standard deviation of
    /// 65.54 USD where the real one is 4_294_967.30 USD — a lie by a factor
    /// of 65_536.
    #[test]
    fn test_b0_overflow_attack_is_blocked_by_range_check() {
        let p0 = 3_000_000u64;
        let delta = 1u64 << 32;
        let attack = LeafData::new(0, p0 + delta);

        // Unchecked circuit: the attack succeeds and the lie is visible.
        let unchecked = B0Circuit::new_unchecked();
        let proof = unchecked
            .prove(p0, attack, LeafData::new(1, p0 + delta))
            .expect("unchecked circuit accepts anything");
        unchecked.data.verify(proof.clone()).expect("and the proof verifies");

        let reported_sumsq = proof.public_inputs[7].to_canonical_u64();
        let true_sumsq = 2u128 * (delta as u128) * (delta as u128);

        assert_eq!(reported_sumsq, 8_589_934_590, "wrapped value");
        assert!(
            (true_sumsq) > crate::P as u128,
            "the honest value must exceed the modulus for this to be an attack"
        );
        assert!(
            (reported_sumsq as u128) < true_sumsq,
            "the circuit under-reports the variance"
        );
        println!(
            "\n[Soundness] unchecked circuit reports sumsq={reported_sumsq}, true value {true_sumsq}"
        );

        // Checked circuit: same witness must not produce a verifying proof.
        let checked = B0Circuit::new();
        assert!(
            is_rejected(&checked, p0, attack, LeafData::new(1, p0 + delta)),
            "the range check must block the overflow attack"
        );
    }
}
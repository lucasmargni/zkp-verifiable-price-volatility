use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::PoseidonGoldilocksConfig;

use crate::merkle::{F, LeafData};
use crate::{MAX_DEV, RANGE_BITS};

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
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // 1. Private witnesses
        let p0 = builder.add_virtual_target();
        let left_index = builder.add_virtual_target();
        let left_price = builder.add_virtual_target();
        let right_index = builder.add_virtual_target();
        let right_price = builder.add_virtual_target();

        let max_dev_target = builder.constant(F::from_canonical_u64(MAX_DEV));

        // 2. In-circuit Map for Left Leaf with strict 23-bit decomposition
        let delta_l = builder.sub(left_price, p0);
        let shifted_l = builder.add(delta_l, max_dev_target);
        let _bits_l = builder.split_le(shifted_l, RANGE_BITS);
        let delta_l_sq = builder.mul(delta_l, delta_l);

        // 3. In-circuit Map for Right Leaf with strict 23-bit decomposition
        let delta_r = builder.sub(right_price, p0);
        let shifted_r = builder.add(delta_r, max_dev_target);
        let _bits_r = builder.split_le(shifted_r, RANGE_BITS);
        let delta_r_sq = builder.mul(delta_r, delta_r);

        // 4. In-circuit Base Reduce: cnt = 2, sum = delta_l + delta_r, sumsq = delta_l_sq + delta_r_sq
        let cnt = builder.constant(F::from_canonical_u64(2));
        let sum = builder.add(delta_l, delta_r);
        let sumsq = builder.add(delta_l_sq, delta_r_sq);

        // 5. In-circuit Poseidon Hashes
        let left_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(vec![left_index, left_price]);
        let right_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(vec![right_index, right_price]);

        let mut parent_inputs = Vec::with_capacity(8);
        parent_inputs.extend_from_slice(&left_hash.elements);
        parent_inputs.extend_from_slice(&right_hash.elements);
        let parent_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(parent_inputs);

        // 6. Public Inputs: (C, P0, cnt, sum, sumsq)
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
    use crate::to_field;
    use std::time::Instant;

    #[test]
    fn test_b0_completeness_and_measure_h() {
        let p0 = 3_000_000u64;
        let left = LeafData::new(0, 3_000_500);
        let right = LeafData::new(1, 2_999_250);

        let circuit = B0Circuit::new();

        // 1. Measure witness generation and proof time (h-related benchmark baseline)
        let start = Instant::now();
        let proof = circuit.prove(p0, left, right).expect("B0 proving must succeed");
        let proving_time = start.elapsed();
        println!("\n[Benchmark] B0 prove time (leaf level): {:?}", proving_time);

        // 2. Verify proof
        let verify_start = Instant::now();
        circuit.data.verify(proof.clone()).expect("B0 verification must succeed");
        println!("[Benchmark] B0 verify time: {:?}", verify_start.elapsed());

        // 3. Check public outputs
        let expected_parent_hash = hash_children(left.hash(), right.hash());
        let expected_delta_l = left.price as i64 - p0 as i64;
        let expected_delta_r = right.price as i64 - p0 as i64;
        let expected_sum = to_field(expected_delta_l + expected_delta_r);
        let expected_sumsq = (expected_delta_l * expected_delta_l + expected_delta_r * expected_delta_r) as u64;

        let pis = &proof.public_inputs;
        assert_eq!(&pis[0..4], &expected_parent_hash.elements);
        assert_eq!(pis[4], F::from_canonical_u64(p0));
        assert_eq!(pis[5], F::from_canonical_u64(2)); // cnt
        assert_eq!(pis[6], F::from_canonical_u64(expected_sum));
        assert_eq!(pis[7], F::from_canonical_u64(expected_sumsq));
    }

    #[test]
    #[should_panic]
    fn test_b0_rejects_out_of_range() {
        let p0 = 3_000_000u64;
        let left = LeafData::new(0, p0);
        // Exceed 23-bit budget (shifted value >= 2^23)
        let exceeding_price = p0 + (1 << RANGE_BITS);
        let right = LeafData::new(1, exceeding_price);

        let circuit = B0Circuit::new();
        // This must panic due to unsatisfiable bit-decomposition constraints
        let _ = circuit.prove(p0, left, right);
    }
}
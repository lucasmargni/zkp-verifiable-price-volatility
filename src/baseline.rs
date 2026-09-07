use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;

use crate::merkle::{F, LeafData};
use crate::{MAX_DEV, RANGE_BITS};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
pub type BaselineProof = ProofWithPublicInputs<F, C, D>;

/// Targets for feeding witness data into the monolithic baseline circuit.
pub struct MonolithicTargets {
    pub p0: Target,
    pub leaf_indices: Vec<Target>,
    pub leaf_prices: Vec<Target>,
    pub root_hash: HashOutTarget,
    pub cnt: Target,
    pub sum: Target,
    pub sumsq: Target,
}

/// A monolithic circuit proving price volatility over N leaves in a single flat circuit without recursion.
pub struct MonolithicBaselineCircuit {
    pub n_leaves: usize,
    pub data: CircuitData<F, C, D>,
    pub targets: MonolithicTargets,
}

impl MonolithicBaselineCircuit {
    /// Builds the monolithic circuit for a fixed power-of-two number of leaves.
    pub fn new(n_leaves: usize) -> Self {
        assert!(n_leaves >= 2 && n_leaves.is_power_of_two(), "n_leaves must be a power of two >= 2");
        let height = n_leaves.trailing_zeros() as usize;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let p0 = builder.add_virtual_target();
        let max_dev_target = builder.constant(F::from_canonical_u64(MAX_DEV));

        let mut leaf_indices = Vec::with_capacity(n_leaves);
        let mut leaf_prices = Vec::with_capacity(n_leaves);
        let mut leaf_hashes = Vec::with_capacity(n_leaves);

        let mut current_cnt = builder.zero();
        let mut current_sum = builder.zero();
        let mut current_sumsq = builder.zero();

        // 1. In-circuit Map and Leaf Hashing for all N leaves
        for _ in 0..n_leaves {
            let idx = builder.add_virtual_target();
            let price = builder.add_virtual_target();

            leaf_indices.push(idx);
            leaf_prices.push(price);

            // Map: delta = price - p0
            let delta = builder.sub(price, p0);
            let shifted = builder.add(delta, max_dev_target);
            let _bits = builder.split_le(shifted, RANGE_BITS);
            let delta_sq = builder.mul(delta, delta);

            // Accumulate
            let one = builder.one();
            current_cnt = builder.add(current_cnt, one);
            current_sum = builder.add(current_sum, delta);
            current_sumsq = builder.add(current_sumsq, delta_sq);

            // Leaf Poseidon hash: H(index || price)
            let h = builder.hash_n_to_hash_no_pad::<PoseidonHash>(vec![idx, price]);
            leaf_hashes.push(h);
        }

        // 2. Monolithic Merkle tree reduction in-circuit
        let mut current_level = leaf_hashes;
        for _ in 0..height {
            let mut next_level = Vec::with_capacity(current_level.len() / 2);
            for chunk in current_level.chunks_exact(2) {
                let mut inputs = Vec::with_capacity(8);
                inputs.extend_from_slice(&chunk[0].elements);
                inputs.extend_from_slice(&chunk[1].elements);
                let parent = builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs);
                next_level.push(parent);
            }
            current_level = next_level;
        }

        let root_hash = current_level[0];

        // 3. Register public inputs: (Root, P0, cnt, sum, sumsq)
        builder.register_public_inputs(&root_hash.elements);
        builder.register_public_input(p0);
        builder.register_public_input(current_cnt);
        builder.register_public_input(current_sum);
        builder.register_public_input(current_sumsq);

        let data = builder.build::<C>();

        let targets = MonolithicTargets {
            p0,
            leaf_indices,
            leaf_prices,
            root_hash,
            cnt: current_cnt,
            sum: current_sum,
            sumsq: current_sumsq,
        };

        Self {
            n_leaves,
            data,
            targets,
        }
    }

    /// Generates a monolithic proof for the given leaves and P0.
    pub fn prove(&self, leaves: &[LeafData], p0: u64) -> anyhow::Result<BaselineProof> {
        assert_eq!(leaves.len(), self.n_leaves);
        let mut pw = PartialWitness::new();

        pw.set_target(self.targets.p0, F::from_canonical_u64(p0));

        for (i, leaf) in leaves.iter().enumerate() {
            pw.set_target(self.targets.leaf_indices[i], F::from_canonical_u64(leaf.index));
            pw.set_target(self.targets.leaf_prices[i], F::from_canonical_u64(leaf.price));
        }

        self.data.prove(pw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::from_field;
    use crate::merkle::MerkleTree;
    use plonky2::field::types::PrimeField64;
    use std::time::Instant;

    #[test]
    fn test_monolithic_baseline_correctness() {
        let n_leaves = 4;
        let p0 = 3_000_000u64;
        let leaves: Vec<LeafData> = (0..n_leaves)
            .map(|i| LeafData::new(i as u64, 3_000_000 + (i as u64) * 500))
            .collect();

        let tree = MerkleTree::new(leaves.clone());
        let baseline = MonolithicBaselineCircuit::new(n_leaves);

        println!("\nProving monolithic baseline (4 leaves)...");
        let start = Instant::now();
        let proof = baseline.prove(&leaves, p0).expect("Monolithic proving failed");
        let elapsed = start.elapsed();
        println!("[Benchmark] Monolithic baseline prove time (4 leaves): {:?}", elapsed);

        // Verify proof
        baseline.data.verify(proof.clone()).expect("Monolithic verification failed");

        let pis = &proof.public_inputs;
        assert_eq!(&pis[0..4], &tree.root().elements);
        assert_eq!(pis[4].to_canonical_u64(), p0);
        assert_eq!(pis[5].to_canonical_u64(), n_leaves as u64);

        let expected_sum: i64 = leaves.iter().map(|l| l.price as i64 - p0 as i64).sum();
        let expected_sumsq: u64 = leaves
            .iter()
            .map(|l| {
                let d = l.price as i64 - p0 as i64;
                (d * d) as u64
            })
            .sum();

        assert_eq!(from_field(pis[6].to_canonical_u64()), expected_sum);
        assert_eq!(pis[7].to_canonical_u64(), expected_sumsq);
    }
}
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;

use crate::circuit_b0::B0Circuit;
use crate::circuit_bi::BiCircuit;
use crate::merkle::{F, LeafData, MerkleTree};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
pub type Proof = ProofWithPublicInputs<F, C, D>;

/// The Reckle proof data structure (Lambda) containing hierarchical circuits
/// and memoized recursive SNARK proofs across all tree levels.
pub struct ReckleBatchTree {
    pub p0: u64,
    pub merkle_tree: MerkleTree,
    pub b0_circuit: B0Circuit,
    pub bi_circuits: Vec<BiCircuit>,
    /// Memoized proofs per level:
    /// `proofs_by_level[0]` holds B0 proofs, `proofs_by_level[h-1]` holds the single root proof.
    pub proofs_by_level: Vec<Vec<Proof>>,
}

impl ReckleBatchTree {
    /// Builds the full tree from bottom to top, initializing Lambda with proofs at every level.
    pub fn new(leaves: Vec<LeafData>, p0: u64) -> Self {
        let n = leaves.len();
        assert!(n >= 2 && n.is_power_of_two(), "Leaf count must be power of two >= 2");
        let height = n.trailing_zeros() as usize;

        let merkle_tree = MerkleTree::new(leaves.clone());

        // 1. Build and prove base level B0
        let b0_circuit = B0Circuit::new();
        let mut level_0_proofs = Vec::with_capacity(n / 2);
        for chunk in leaves.chunks_exact(2) {
            let proof = b0_circuit
                .prove(p0, chunk[0], chunk[1])
                .expect("Initial B0 proof generation failed");
            level_0_proofs.push(proof);
        }

        let mut proofs_by_level = Vec::with_capacity(height);
        proofs_by_level.push(level_0_proofs);

        // 2. Build and prove recursive levels B1 .. Bh-1
        let mut bi_circuits = Vec::with_capacity(height - 1);
        let mut current_verifier_data = b0_circuit.data.verifier_data();

        for level in 0..(height - 1) {
            let bi_circuit = BiCircuit::new(&current_verifier_data);
            let prev_proofs = &proofs_by_level[level];
            let mut next_proofs = Vec::with_capacity(prev_proofs.len() / 2);

            for chunk in prev_proofs.chunks_exact(2) {
                let proof = bi_circuit
                    .prove(&chunk[0], &chunk[1])
                    .expect("Recursive proof generation failed");
                next_proofs.push(proof);
            }

            current_verifier_data = bi_circuit.data.verifier_data();
            bi_circuits.push(bi_circuit);
            proofs_by_level.push(next_proofs);
        }

        Self {
            p0,
            merkle_tree,
            b0_circuit,
            bi_circuits,
            proofs_by_level,
        }
    }

    /// Returns a reference to the root batch proof.
    pub fn root_proof(&self) -> &Proof {
        &self.proofs_by_level.last().unwrap()[0]
    }

    /// Verifies the current root batch proof using the top-level circuit verifier.
    pub fn verify_root_proof(&self) -> anyhow::Result<()> {
        if self.bi_circuits.is_empty() {
            self.b0_circuit.data.verify(self.root_proof().clone())
        } else {
            self.bi_circuits.last().unwrap().data.verify(self.root_proof().clone())
        }
    }

    /// Updates a single leaf and updates the batch proof in O(log n) time by only
    /// recomputing proofs on the direct path from the leaf to the root.
    pub fn update_leaf(&mut self, leaf_idx: usize, new_leaf: LeafData) {
        // 1. Update off-circuit Merkle tree
        self.merkle_tree.update_leaf(leaf_idx, new_leaf);

        // 2. Recompute affected B0 leaf proof
        let pair_idx = leaf_idx / 2;
        let left_leaf = self.merkle_tree.leaves[pair_idx * 2];
        let right_leaf = self.merkle_tree.leaves[pair_idx * 2 + 1];

        let mut current_proof = self
            .b0_circuit
            .prove(self.p0, left_leaf, right_leaf)
            .expect("Updated B0 proof failed");
        self.proofs_by_level[0][pair_idx] = current_proof.clone();

        // 3. Ascend through recursive levels, updating exactly one proof per level
        let mut current_idx = pair_idx;
        for level in 0..self.bi_circuits.len() {
            let is_right = (current_idx & 1) == 1;
            let sibling_idx = current_idx ^ 1;
            let parent_idx = current_idx / 2;

            let sibling_proof = &self.proofs_by_level[level][sibling_idx];

            let parent_proof = if is_right {
                self.bi_circuits[level]
                    .prove(sibling_proof, &current_proof)
                    .expect("Updated recursive proof failed")
            } else {
                self.bi_circuits[level]
                    .prove(&current_proof, sibling_proof)
                    .expect("Updated recursive proof failed")
            };

            self.proofs_by_level[level + 1][parent_idx] = parent_proof.clone();
            current_proof = parent_proof;
            current_idx = parent_idx;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::from_field;
    use plonky2::field::types::PrimeField64;
    use std::time::Instant;

    #[test]
    fn test_reckle_tree_assembly_and_update_log_n() {
        let p0 = 3_000_000u64;
        let mut leaves: Vec<LeafData> = (0..4)
            .map(|i| LeafData::new(i, 3_000_000 + (i as u64) * 1_000))
            .collect();

        println!("\nInitializing Reckle Batch Tree (4 leaves, height 2)...");
        let start_init = Instant::now();
        let mut tree = ReckleBatchTree::new(leaves.clone(), p0);
        println!("Initialization complete in {:?}", start_init.elapsed());

        // 1. Verify initial root proof
        tree.verify_root_proof().expect("Initial root proof verification must succeed");

        let initial_root_proof = tree.root_proof().clone();
        let pis = &initial_root_proof.public_inputs;
        assert_eq!(&pis[0..4], &tree.merkle_tree.root().elements);
        assert_eq!(pis[5].to_canonical_u64(), 4); // cnt = 4

        // 2. Perform O(log n) update on leaf at index 2
        let new_leaf = LeafData::new(2, 3_050_000);
        leaves[2] = new_leaf;

        println!("\nPerforming O(log n) update on leaf 2...");
        let start_update = Instant::now();
        tree.update_leaf(2, new_leaf);
        let update_duration = start_update.elapsed();
        println!("[Benchmark] UpdBatchProof time: {:?}", update_duration);

        // 3. Verify updated root proof
        tree.verify_root_proof().expect("Updated root proof verification must succeed");

        // Confirm root digest and aggregates changed properly
        let updated_proof = tree.root_proof();
        let updated_pis = &updated_proof.public_inputs;

        assert_eq!(&updated_pis[0..4], &tree.merkle_tree.root().elements);
        assert_ne!(&updated_pis[0..4], &initial_root_proof.public_inputs[0..4]);

        let expected_sum: i64 = leaves.iter().map(|l| l.price as i64 - p0 as i64).sum();
        let expected_sumsq: u64 = leaves
            .iter()
            .map(|l| {
                let d = l.price as i64 - p0 as i64;
                (d * d) as u64
            })
            .sum();

        assert_eq!(from_field(updated_pis[6].to_canonical_u64()), expected_sum);
        assert_eq!(updated_pis[7].to_canonical_u64(), expected_sumsq);
    }
}
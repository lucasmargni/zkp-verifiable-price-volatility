use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOut;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::Hasher;

pub type F = GoldilocksField;
pub type Digest = HashOut<F>;

/// Represents a single leaf in the price Merkle tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeafData {
    pub index: u64,
    pub price: u64,
}

impl LeafData {
    pub fn new(index: u64, price: u64) -> Self {
        Self { index, price }
    }

    /// Computes the Poseidon commitment for this leaf: H(index || price).
    pub fn hash(&self) -> Digest {
        let inputs = [
            F::from_canonical_u64(self.index),
            F::from_canonical_u64(self.price),
        ];
        PoseidonHash::hash_no_pad(&inputs)
    }
}

/// Computes the parent node digest from two child digests: H(left || right).
pub fn hash_children(left: Digest, right: Digest) -> Digest {
    let mut inputs = Vec::with_capacity(8);
    inputs.extend_from_slice(&left.elements);
    inputs.extend_from_slice(&right.elements);
    PoseidonHash::hash_no_pad(&inputs)
}

/// Off-circuit Merkle tree supporting O(log n) single-leaf updates.
#[derive(Clone, Debug)]
pub struct MerkleTree {
    pub leaves: Vec<LeafData>,
    /// Layered node representation:
    /// `layers[0]` holds leaf hashes, `layers[height]` holds the single root digest.
    pub layers: Vec<Vec<Digest>>,
}

impl MerkleTree {
    /// Constructs a full binary Merkle tree from a power-of-two slice of leaves.
    pub fn new(leaves: Vec<LeafData>) -> Self {
        let n = leaves.len();
        assert!(n > 0 && n.is_power_of_two(), "Leaf count must be a non-zero power of two");

        let leaf_hashes: Vec<Digest> = leaves.iter().map(|l| l.hash()).collect();
        let height = n.trailing_zeros() as usize;

        let mut layers = Vec::with_capacity(height + 1);
        layers.push(leaf_hashes.clone());

        let mut current_layer = leaf_hashes;
        for _ in 0..height {
            let mut next_layer = Vec::with_capacity(current_layer.len() / 2);
            for chunk in current_layer.chunks_exact(2) {
                next_layer.push(hash_children(chunk[0], chunk[1]));
            }
            layers.push(next_layer.clone());
            current_layer = next_layer;
        }

        Self { leaves, layers }
    }

    /// Returns the tree root digest.
    pub fn root(&self) -> Digest {
        self.layers.last().expect("Tree must have at least one layer")[0]
    }

    /// Returns the tree height (levels above the leaf layer).
    pub fn height(&self) -> usize {
        self.layers.len() - 1
    }

    /// Generates a standard Merkle inclusion proof for a given leaf index.
    pub fn prove(&self, mut index: usize) -> Vec<Digest> {
        let h = self.height();
        let mut proof = Vec::with_capacity(h);

        for level in 0..h {
            let sibling_index = index ^ 1;
            proof.push(self.layers[level][sibling_index]);
            index /= 2;
        }

        proof
    }

    /// Updates a single leaf and recomputes the Merkle path to the root in O(log n) time.
    pub fn update_leaf(&mut self, mut index: usize, new_leaf: LeafData) {
        self.leaves[index] = new_leaf;
        let mut current_hash = new_leaf.hash();
        self.layers[0][index] = current_hash;

        for level in 0..self.height() {
            let is_right = (index & 1) == 1;
            let parent_index = index / 2;
            let sibling_hash = self.layers[level][index ^ 1];

            current_hash = if is_right {
                hash_children(sibling_hash, current_hash)
            } else {
                hash_children(current_hash, sibling_hash)
            };

            self.layers[level + 1][parent_index] = current_hash;
            index = parent_index;
        }
    }

    /// Verifies a Merkle inclusion proof against an expected root digest.
    pub fn verify_proof(leaf: &LeafData, mut index: usize, proof: &[Digest], root: Digest) -> bool {
        let mut current_hash = leaf.hash();

        for &sibling in proof {
            let is_right = (index & 1) == 1;
            current_hash = if is_right {
                hash_children(sibling, current_hash)
            } else {
                hash_children(current_hash, sibling)
            };
            index /= 2;
        }

        current_hash == root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_construction_and_verification() {
        let leaves: Vec<LeafData> = (0..8)
            .map(|i| LeafData::new(i, 3_000_000 + i * 10_000))
            .collect();

        let tree = MerkleTree::new(leaves.clone());
        let root = tree.root();

        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.prove(i);
            assert_eq!(proof.len(), 3);
            assert!(MerkleTree::verify_proof(leaf, i, &proof, root));
        }
    }

    #[test]
    fn test_merkle_update_leaf() {
        let mut leaves: Vec<LeafData> = (0..16)
            .map(|i| LeafData::new(i, 2_500_000 + i * 5_000))
            .collect();

        let mut tree = MerkleTree::new(leaves.clone());

        // Update leaf at index 5
        let updated_leaf = LeafData::new(5, 3_100_000);
        tree.update_leaf(5, updated_leaf);
        leaves[5] = updated_leaf;

        // Reconstruct from scratch to ensure identical root
        let expected_tree = MerkleTree::new(leaves);
        assert_eq!(tree.root(), expected_tree.root());

        // Verify that the updated proof remains valid
        let proof = tree.prove(5);
        assert!(MerkleTree::verify_proof(&updated_leaf, 5, &proof, tree.root()));
    }

    #[test]
    fn test_merkle_against_reference_vectors() {
        use serde_json::Value;
        use std::fs;
        use crate::{from_field, map_leaf, reduce, Acc};

        // Load reference vectors generated in Step 2
        let path = "testdata/vectors.json";
        let content = fs::read_to_string(path)
            .or_else(|_| fs::read_to_string("../testdata/vectors.json"))
            .expect("Failed to read testdata/vectors.json");

        let json: Value = serde_json::from_str(&content).expect("Invalid JSON in vectors.json");
        let cases = json["cases"].as_array().expect("Missing cases array");

        // Helper to run Merkle tree construction and aggregation on a valid test case
        let run_case = |case: &Value| {
            let p0 = case["p0_enc"].as_u64().expect("Missing p0_enc");
            let expected = &case["expected"];
            let expected_cnt = expected["cnt"].as_u64().expect("Missing expected.cnt");
            let expected_sum = expected["sum_signed"].as_i64().expect("Missing expected.sum_signed");
            let expected_sumsq = expected["sumsq"].as_u64().expect("Missing expected.sumsq");

            let prices_json = case["prices_enc"].as_array().expect("Missing prices_enc");
            assert_eq!(prices_json.len() as u64, expected_cnt);

            // 1. Build leaves for off-circuit Merkle tree
            let mut merkle_leaves = Vec::with_capacity(prices_json.len());
            for (i, p) in prices_json.iter().enumerate() {
                let price = p.as_u64().expect("Invalid price entry");
                merkle_leaves.push(LeafData::new(i as u64, price));
            }

            // 2. Build Merkle tree
            let tree = MerkleTree::new(merkle_leaves.clone());
            assert_eq!(tree.leaves.len() as u64, expected_cnt);

            // 3. Verify that Map/Reduce aggregates match the vector expectations
            let mut acc_leaves: Vec<Acc> = merkle_leaves
                .iter()
                .map(|leaf| map_leaf(leaf.price, p0).expect("map_leaf should succeed"))
                .collect();

            // Fold the accumulator up to root
            while acc_leaves.len() > 1 {
                let mut next_level = Vec::with_capacity(acc_leaves.len() / 2);
                for chunk in acc_leaves.chunks_exact(2) {
                    next_level.push(reduce(chunk[0], chunk[1]));
                }
                acc_leaves = next_level;
            }
            let final_acc = acc_leaves[0];

            assert_eq!(final_acc.cnt, expected_cnt);
            assert_eq!(from_field(final_acc.sum), expected_sum);
            assert_eq!(final_acc.sumsq, expected_sumsq);

            // 4. Update a leaf and verify root update and proof
            let update_idx = prices_json.len() / 2;
            let old_root = tree.root();
            let mut updated_tree = tree.clone();
            let new_leaf = LeafData::new(update_idx as u64, p0 + 10_000);
            updated_tree.update_leaf(update_idx, new_leaf);

            assert_ne!(old_root, updated_tree.root());
            let proof = updated_tree.prove(update_idx);
            assert!(MerkleTree::verify_proof(&new_leaf, update_idx, &proof, updated_tree.root()));
        };

        // Test with the 4-leaf case ("tiny_4")
        run_case(&cases[0]);

        // Test with the full 4096-leaf case if present
        if let Some(case_4096) = cases.iter().find(|c| c["n_leaves"].as_u64() == Some(4096) && !c["should_reject"].as_bool().unwrap_or(true)) {
            run_case(case_4096);
        }
    }
}
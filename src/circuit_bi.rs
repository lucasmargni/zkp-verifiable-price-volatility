use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData};
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};

use crate::merkle::F;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;

/// Targets for feeding inner child proofs into recursive circuit Bi.
pub struct BiTargets {
    pub left_proof: ProofWithPublicInputsTarget<D>,
    pub right_proof: ProofWithPublicInputsTarget<D>,
    pub parent_hash: HashOutTarget,
    pub p0: Target,
    pub cnt: Target,
    pub sum: Target,
    pub sumsq: Target,
}

/// Helper encapsulating recursive circuit Bi data and targets.
pub struct BiCircuit {
    pub data: CircuitData<F, C, D>,
    pub targets: BiTargets,
}

impl BiCircuit {
    /// Builds circuit Bi which recursively verifies two proofs from `child_verifier_data`.
    pub fn new(child_verifier_data: &VerifierCircuitData<F, C, D>) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // 1. Hardcode child verification key (vk_{i-1}) in circuit
        let child_vk_target = builder.constant_verifier_data(&child_verifier_data.verifier_only);

        // 2. Virtual targets for left and right child proofs
        let left_proof = builder.add_virtual_proof_with_pis(&child_verifier_data.common);
        let right_proof = builder.add_virtual_proof_with_pis(&child_verifier_data.common);

        // 3. In-circuit recursive verifications
        builder.verify_proof::<C>(&left_proof, &child_vk_target, &child_verifier_data.common);
        builder.verify_proof::<C>(&right_proof, &child_vk_target, &child_verifier_data.common);

        // 4. Parse children public inputs: [C[0..4], p0, cnt, sum, sumsq]
        let left_hash_targets = &left_proof.public_inputs[0..4];
        let p0_l = left_proof.public_inputs[4];
        let cnt_l = left_proof.public_inputs[5];
        let sum_l = left_proof.public_inputs[6];
        let sumsq_l = left_proof.public_inputs[7];

        let right_hash_targets = &right_proof.public_inputs[0..4];
        let p0_r = right_proof.public_inputs[4];
        let cnt_r = right_proof.public_inputs[5];
        let sum_r = right_proof.public_inputs[6];
        let sumsq_r = right_proof.public_inputs[7];

        // Enforce identical reference price P0
        builder.connect(p0_l, p0_r);
        let p0 = p0_l;

        // 5. In-circuit Reduce operations
        let cnt = builder.add(cnt_l, cnt_r);
        let sum = builder.add(sum_l, sum_r);
        let sumsq = builder.add(sumsq_l, sumsq_r);

        // 6. Merkle parent hash: C = H(C_L || C_R)
        let mut parent_inputs = Vec::with_capacity(8);
        parent_inputs.extend_from_slice(left_hash_targets);
        parent_inputs.extend_from_slice(right_hash_targets);
        let parent_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(parent_inputs);

        // 7. Register consolidated Public Inputs
        builder.register_public_inputs(&parent_hash.elements);
        builder.register_public_input(p0);
        builder.register_public_input(cnt);
        builder.register_public_input(sum);
        builder.register_public_input(sumsq);

        let data = builder.build::<C>();

        let targets = BiTargets {
            left_proof,
            right_proof,
            parent_hash,
            p0,
            cnt,
            sum,
            sumsq,
        };

        Self { data, targets }
    }

    /// Fills witness with child proofs and generates the recursive proof.
    pub fn prove(
        &self,
        left_proof: &ProofWithPublicInputs<F, C, D>,
        right_proof: &ProofWithPublicInputs<F, C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::new();

        pw.set_proof_with_pis_target(&self.targets.left_proof, left_proof);
        pw.set_proof_with_pis_target(&self.targets.right_proof, right_proof);

        self.data.prove(pw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit_b0::B0Circuit;
    use crate::from_field;
    use crate::merkle::{hash_children, LeafData};
    use plonky2::field::types::PrimeField64;
    use std::time::Instant;

    #[test]
    fn test_bi_two_level_recursion_and_measure_r() {
        let p0 = 3_000_000u64;

        // 4 leaves (indices 0..4)
        let leaves = [
            LeafData::new(0, 3_000_500),
            LeafData::new(1, 2_999_250),
            LeafData::new(2, 3_001_000),
            LeafData::new(3, 3_000_000),
        ];

        // 1. Build level 0 (B0)
        let b0_circuit = B0Circuit::new();

        println!("\nGenerating level 0 proofs (B0)...");
        let proof_l0_left = b0_circuit
            .prove(p0, leaves[0], leaves[1])
            .expect("B0 left proof failed");
        let proof_l0_right = b0_circuit
            .prove(p0, leaves[2], leaves[3])
            .expect("B0 right proof failed");

        // 2. Build level 1 recursive circuit (B1)
        let b1_circuit = BiCircuit::new(&b0_circuit.data.verifier_data());

        // 3. Measure recursive proof time (parameter r from paper)
        let r_start = Instant::now();
        let b1_proof = b1_circuit
            .prove(&proof_l0_left, &proof_l0_right)
            .expect("B1 recursive proof failed");
        let r_duration = r_start.elapsed();
        println!("\n[Benchmark] r (recursive step prove time): {:?}", r_duration);

        // 4. Verify root proof
        let v_start = Instant::now();
        b1_circuit
            .data
            .verify(b1_proof.clone())
            .expect("B1 verification failed");
        println!("[Benchmark] B1 verify time: {:?}", v_start.elapsed());

        // 5. Check expected public outputs off-circuit
        let h_l0_left = hash_children(leaves[0].hash(), leaves[1].hash());
        let h_l0_right = hash_children(leaves[2].hash(), leaves[3].hash());
        let expected_root = hash_children(h_l0_left, h_l0_right);

        let deltas: Vec<i64> = leaves.iter().map(|l| l.price as i64 - p0 as i64).collect();
        let expected_sum: i64 = deltas.iter().sum();
        let expected_sumsq: u64 = deltas.iter().map(|&d| (d * d) as u64).sum();

        let pis = &b1_proof.public_inputs;
        assert_eq!(&pis[0..4], &expected_root.elements);
        assert_eq!(pis[4].to_canonical_u64(), p0);
        assert_eq!(pis[5].to_canonical_u64(), 4); // cnt = 4
        assert_eq!(from_field(pis[6].to_canonical_u64()), expected_sum);
        assert_eq!(pis[7].to_canonical_u64(), expected_sumsq);
    }
}
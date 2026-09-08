use reckle_volatility::baseline::MonolithicBaselineCircuit;
use reckle_volatility::merkle::LeafData;
use reckle_volatility::reckle_tree::ReckleBatchTree;

#[test]
fn test_reckle_vs_monolithic_consistency() {
    let p0 = 3_000_000u64;
    let leaves: Vec<LeafData> = (0..4)
        .map(|i| LeafData::new(i as u64, 3_000_000 + (i as u64) * 2_500))
        .collect();

    // 1. Reckle Tree Proof
    let reckle = ReckleBatchTree::new(leaves.clone(), p0);
    reckle.verify_root_proof().expect("Reckle root proof verification failed");
    let reckle_pis = &reckle.root_proof().public_inputs;

    // 2. Monolithic Baseline Proof
    let baseline = MonolithicBaselineCircuit::new(4);
    let mono_proof = baseline.prove(&leaves, p0).expect("Monolithic proof failed");
    baseline.data.verify(mono_proof.clone()).expect("Monolithic verification failed");
    let mono_pis = &mono_proof.public_inputs;

    // 3. Compare Public Inputs: (Root Hash, P0, cnt, sum, sumsq)
    assert_eq!(&reckle_pis[0..4], &mono_pis[0..4], "Root hashes must match");
    assert_eq!(reckle_pis[4], mono_pis[4], "P0 must match");
    assert_eq!(reckle_pis[5], mono_pis[5], "cnt must match");
    assert_eq!(reckle_pis[6], mono_pis[6], "sum must match");
    assert_eq!(reckle_pis[7], mono_pis[7], "sumsq must match");
}
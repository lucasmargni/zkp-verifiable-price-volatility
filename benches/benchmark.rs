use reckle_volatility::baseline::MonolithicBaselineCircuit;
use reckle_volatility::circuit_b0::B0Circuit;
use reckle_volatility::circuit_bi::BiCircuit;
use reckle_volatility::merkle::LeafData;
use reckle_volatility::reckle_tree::ReckleBatchTree;
use std::time::Instant;

fn main() {
    println!("============================================================");
    println!("     RECKLE TREES ZK-SNARK BENCHMARK SUITE (STEP 9)        ");
    println!("============================================================\n");

    let p0 = 3_000_000u64;

    // 1. Measure h and base circuit proving time
    println!("[1/4] Benchmarking Base Level B0 (Leaf Level)...");
    let leaf_0 = LeafData::new(0, 3_000_500);
    let leaf_1 = LeafData::new(1, 2_999_250);

    let b0_circuit = B0Circuit::new();
    let b0_start = Instant::now();
    let b0_proof_left = b0_circuit.prove(p0, leaf_0, leaf_1).expect("B0 prove failed");
    let b0_time = b0_start.elapsed();

    let leaf_2 = LeafData::new(2, 3_001_000);
    let leaf_3 = LeafData::new(3, 3_000_000);
    let b0_proof_right = b0_circuit.prove(p0, leaf_2, leaf_3).expect("B0 prove failed");

    let b0_v_start = Instant::now();
    b0_circuit.data.verify(b0_proof_left.clone()).expect("B0 verify failed");
    let b0_v_time = b0_v_start.elapsed();

    println!("  -> B0 Proving Time:  {:?}", b0_time);
    println!("  -> B0 Verify Time:   {:?}\n", b0_v_time);

    // 2. Measure recursive step r (Bi proving time)
    println!("[2/4] Benchmarking Recursive Step Bi (r parameter)...");
    let bi_circuit = BiCircuit::new(&b0_circuit.data.verifier_data());

    let r_start = Instant::now();
    let bi_proof = bi_circuit.prove(&b0_proof_left, &b0_proof_right).expect("Bi prove failed");
    let r_time = r_start.elapsed();

    let bi_v_start = Instant::now();
    bi_circuit.data.verify(bi_proof).expect("Bi verify failed");
    let bi_v_time = bi_v_start.elapsed();

    println!("  -> Recursive Step Proving (r): {:?}", r_time);
    println!("  -> Recursive Step Verify (v):  {:?}\n", bi_v_time);

    // 3. Compare Reckle O(log n) update vs Monolithic Full Re-proving (N = 4)
    println!("[3/4] Comparing Dynamic Leaf Update: Reckle O(log n) vs Baseline Monolithic...");
    let n_leaves = 4;
    let leaves: Vec<LeafData> = (0..n_leaves)
        .map(|i| LeafData::new(i as u64, 3_000_000 + (i as u64) * 1_000))
        .collect();

    let mut reckle = ReckleBatchTree::new(leaves.clone(), p0);
    let baseline = MonolithicBaselineCircuit::new(n_leaves);

    let updated_leaf = LeafData::new(2, 3_020_000);

    // Time Reckle O(log n) update
    let reckle_upd_start = Instant::now();
    reckle.update_leaf(2, updated_leaf);
    let reckle_upd_time = reckle_upd_start.elapsed();

    // Time Monolithic full re-proof
    let mut updated_leaves = leaves.clone();
    updated_leaves[2] = updated_leaf;
    let mono_start = Instant::now();
    let _ = baseline.prove(&updated_leaves, p0).expect("Monolithic prove failed");
    let mono_time = mono_start.elapsed();

    println!("  -> Reckle O(log n) update time:     {:?}", reckle_upd_time);
    println!("  -> Monolithic Full re-proving time: {:?}", mono_time);
    let speedup = mono_time.as_secs_f64() / reckle_upd_time.as_secs_f64();
    println!("  -> Relative ratio: {:.2}x\n", speedup);

    // 4. Print Summary Table
    println!("============================================================");
    println!("                   SUMMARY TABLE OF METRICS                 ");
    println!("============================================================");
    println!("| Operation                          | Latency             |");
    println!("|------------------------------------|---------------------|");
    println!("| B0 Leaf Prove                      | {:<19?} |", b0_time);
    println!("| B0 Verify                          | {:<19?} |", b0_v_time);
    println!("| Recursive Step (r)                 | {:<19?} |", r_time);
    println!("| Recursive Verify (v)               | {:<19?} |", bi_v_time);
    println!("| Reckle UpdBatchProof (N=4)         | {:<19?} |", reckle_upd_time);
    println!("| Monolithic Re-prove (N=4)          | {:<19?} |", mono_time);
    println!("============================================================");
}
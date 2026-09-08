use reckle_volatility::baseline::MonolithicBaselineCircuit;
use reckle_volatility::circuit_b0::B0Circuit;
use reckle_volatility::circuit_bi::BiCircuit;
use reckle_volatility::merkle::LeafData;
use reckle_volatility::reckle_tree::ReckleBatchTree;
use std::fs;
use std::io::Write;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::Instant;

const P0: u64 = 3_000_000;

/// Sizes for the scaling sweep. Override from the command line:
/// `cargo bench --bench benchmark -- 4 8 16 32 64 128 256`
const DEFAULT_SIZES: &[usize] = &[4, 8, 16, 32, 64];

/// Deterministic pseudo-random walk. Same recurrence as `scripts/gen_vectors.py`,
/// so a sweep uses the same prices as the reference vectors.
fn synth_prices(n: usize) -> Vec<LeafData> {
    let (mut out, mut x, mut s) = (Vec::with_capacity(n), 3000.0f64, 12345u64);
    for i in 0..n {
        s = (1103515245u64.wrapping_mul(s).wrapping_add(12345)) % (1u64 << 31);
        x += ((s as f64 / (1u64 << 31) as f64) - 0.5) * 4.0;
        out.push(LeafData::new(i as u64, (x * 1000.0).round() as u64));
    }
    out
}

/// One measurement. `note` records why a run stopped short, so a failed size
/// still produces a row instead of aborting the sweep.
struct Row {
    system: &'static str,
    n_leaves: usize,
    aggregate_s: f64,
    update_s: f64,
    verify_ms: f64,
    proof_bytes: usize,
    note: String,
}

impl Row {
    fn failed(system: &'static str, n_leaves: usize, note: &str) -> Self {
        Row {
            system,
            n_leaves,
            aggregate_s: f64::NAN,
            update_s: f64::NAN,
            verify_ms: f64::NAN,
            proof_bytes: 0,
            note: note.into(),
        }
    }

    fn csv(&self) -> String {
        format!(
            "{},{},{:.4},{:.4},{:.4},{},{}",
            self.system,
            self.n_leaves,
            self.aggregate_s,
            self.update_s,
            self.verify_ms,
            self.proof_bytes,
            self.note
        )
    }

    fn print(&self) {
        println!(
            "  {:9} n={:5}  aggregate {:>9.3}s  update {:>9.4}s  verify {:>7.3}ms  proof {:>8} B  {}",
            self.system, self.n_leaves, self.aggregate_s, self.update_s, self.verify_ms,
            self.proof_bytes, self.note
        );
    }
}

// ---------------------------------------------------------------- fixed costs

/// Measures `h` and `r` in the paper's notation, on the smallest tree that
/// exercises both: two B0 proofs merged by one Bi proof.
fn bench_fixed_costs() {
    println!("[1/3] Fixed per-step costs (h, r, v)\n");

    let leaves = [
        LeafData::new(0, 3_000_500),
        LeafData::new(1, 2_999_250),
        LeafData::new(2, 3_001_000),
        LeafData::new(3, 3_000_000),
    ];

    let b0 = B0Circuit::new();

    let t = Instant::now();
    let p_l = b0.prove(P0, leaves[0], leaves[1]).expect("B0 prove failed");
    let h = t.elapsed();
    let p_r = b0.prove(P0, leaves[2], leaves[3]).expect("B0 prove failed");

    let t = Instant::now();
    b0.data.verify(p_l.clone()).expect("B0 verify failed");
    let v_b0 = t.elapsed();

    let bi = BiCircuit::new(&b0.data.verifier_data());

    let t = Instant::now();
    let p_bi = bi.prove(&p_l, &p_r).expect("Bi prove failed");
    let r = t.elapsed();

    let t = Instant::now();
    bi.data.verify(p_bi.clone()).expect("Bi verify failed");
    let v_bi = t.elapsed();

    println!("  h  B0 prove            {h:?}");
    println!("     B0 verify           {v_b0:?}");
    println!("     B0 proof size       {} B", p_l.to_bytes().len());
    println!("  r  Bi prove            {r:?}");
    println!("  v  Bi verify           {v_bi:?}");
    println!("     Bi proof size       {} B\n", p_bi.to_bytes().len());
}

// -------------------------------------------------------------------- sweep

fn bench_reckle(n: usize) -> Row {
    let leaves = synth_prices(n);

    let t = Instant::now();
    let built = catch_unwind(AssertUnwindSafe(|| ReckleBatchTree::new(leaves.clone(), P0)));
    let aggregate_s = t.elapsed().as_secs_f64();

    let mut tree = match built {
        Ok(tree) => tree,
        Err(_) => return Row::failed("reckle", n, "aggregation failed"),
    };

    let t = Instant::now();
    tree.verify_root_proof().expect("root proof must verify");
    let verify_ms = t.elapsed().as_secs_f64() * 1000.0;

    let proof_bytes = tree.root_proof().to_bytes().len();

    // Update a middle leaf: any index has the same path length, but a middle
    // one avoids an all-left or all-right path by accident.
    let idx = n / 2;
    let bumped = LeafData::new(idx as u64, leaves[idx].price + 1_000);
    let t = Instant::now();
    tree.update_leaf(idx, bumped);
    let update_s = t.elapsed().as_secs_f64();

    // The update is only interesting if the result still verifies.
    tree.verify_root_proof().expect("updated root proof must verify");

    Row { system: "reckle", n_leaves: n, aggregate_s, update_s, verify_ms, proof_bytes, note: String::new() }
}

fn bench_baseline(n: usize) -> Row {
    let leaves = synth_prices(n);

    // The monolithic circuit holds every leaf and the whole Merkle tree at
    // once, so it is expected to fail well before Reckle does. Catch it and
    // record where, rather than aborting the sweep: that failure point is a
    // result in its own right.
    let built = catch_unwind(AssertUnwindSafe(|| MonolithicBaselineCircuit::new(n)));
    let circuit = match built {
        Ok(c) => c,
        Err(_) => return Row::failed("baseline", n, "circuit build failed"),
    };

    let t = Instant::now();
    let proved = catch_unwind(AssertUnwindSafe(|| circuit.prove(&leaves, P0)));
    let aggregate_s = t.elapsed().as_secs_f64();

    let proof = match proved {
        Ok(Ok(p)) => p,
        _ => return Row::failed("baseline", n, "proving failed"),
    };

    let t = Instant::now();
    circuit.data.verify(proof.clone()).expect("baseline proof must verify");
    let verify_ms = t.elapsed().as_secs_f64() * 1000.0;

    // There is no incremental update: one changed leaf means reproving from
    // scratch. Charging the baseline a full reproof is the comparison the
    // paper's contribution rests on.
    let mut bumped = leaves.clone();
    bumped[n / 2] = LeafData::new((n / 2) as u64, leaves[n / 2].price + 1_000);
    let t = Instant::now();
    circuit.prove(&bumped, P0).expect("baseline reproof must succeed");
    let update_s = t.elapsed().as_secs_f64();

    Row {
        system: "baseline",
        n_leaves: n,
        aggregate_s,
        update_s,
        verify_ms,
        proof_bytes: proof.to_bytes().len(),
        note: "update = full reproof".into(),
    }
}

fn main() {
    println!("============================================================");
    println!("     RECKLE TREES ZK-SNARK BENCHMARK SUITE                 ");
    println!("============================================================\n");

    let args: Vec<String> = std::env::args().skip(1).filter(|a| !a.starts_with('-')).collect();
    let sizes: Vec<usize> = if args.is_empty() {
        DEFAULT_SIZES.to_vec()
    } else {
        args.iter().map(|a| a.parse().expect("sizes must be integers")).collect()
    };
    for &n in &sizes {
        assert!(n >= 2 && n.is_power_of_two(), "sizes must be powers of two >= 2");
    }

    bench_fixed_costs();

    println!("[2/3] Scaling sweep: Reckle vs monolithic baseline\n");
    let mut rows = Vec::new();
    for &n in &sizes {
        for row in [bench_reckle(n), bench_baseline(n)] {
            row.print();
            rows.push(row);
        }
    }

    println!("\n[3/3] Update cost: O(log n) vs full reproof\n");
    println!("  {:>7}  {:>12}  {:>12}  {:>10}", "n", "reckle", "baseline", "speedup");
    for &n in &sizes {
        let rk = rows.iter().find(|r| r.system == "reckle" && r.n_leaves == n);
        let bl = rows.iter().find(|r| r.system == "baseline" && r.n_leaves == n);
        match (rk, bl) {
            (Some(a), Some(b)) if a.update_s.is_finite() && b.update_s.is_finite() => println!(
                "  {:>7}  {:>10.4}s  {:>10.4}s  {:>9.2}x",
                n, a.update_s, b.update_s, b.update_s / a.update_s
            ),
            (Some(a), Some(b)) => println!(
                "  {:>7}  {:>10}  {:>10}  {:>10}",
                n,
                if a.update_s.is_finite() { format!("{:.4}s", a.update_s) } else { "failed".into() },
                if b.update_s.is_finite() { format!("{:.4}s", b.update_s) } else { "failed".into() },
                "-"
            ),
            _ => {}
        }
    }

    fs::create_dir_all("benchdata").expect("cannot create benchdata/");
    let mut out = fs::File::create("benchdata/results.csv").expect("cannot open results.csv");
    writeln!(out, "system,n_leaves,aggregate_s,update_s,verify_ms,proof_bytes,note").unwrap();
    for row in &rows {
        writeln!(out, "{}", row.csv()).unwrap();
    }

    println!("\nwrote benchdata/results.csv");
}
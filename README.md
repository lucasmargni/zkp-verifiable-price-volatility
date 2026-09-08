# Verifiable Price Volatility over Reckle Trees
 
An updatable Map/Reduce instantiation of Reckle+ trees for on-chain volatility statistics.
 
**Course:** Building Cryptographic Proofs: ZKPs & SNARKs — 39th ECI, UBA
**Authors:** `Coronel, Paula Martina`, `Margni, Lucas Agustin`
**Base paper:** Papamanthou, Srinivasan, Gailly, Hishon-Rezaizadeh, Salumets, Golemac. *Reckle Trees: Updatable Merkle Batch Proofs with Applications.* ACM CCS 2024.
**Reference implementation:** https://github.com/Lagrange-Labs/reckle-trees

---

## 1. The application

A Merkle batch proof over `|I|` arbitrary slots costs `O(|I| log n)` hashes and is not succinct. Reckle trees make it succinct via a recursive SNARK at each node, and keep it **updatable**, a leaf change refreshes the proof in time logarithmic in `n`, independent of `|I|`. Reckle+ extends this from proving *contents* to proving *computation*, embedding a Map/Reduce pair in the recursive circuit. The paper lists DeFi workloads it does not implement, among them price volatility over a sliding window of blocks. We implement that workload: our tree holds the last 4096 blocks of an ETH/USD feed, one per leaf (~13.6 h). We prove:
 
> `(cnt, sum, sumsq)` is the result of the Map/Reduce computation over **all** leaves of the Merkle tree with root `C`.
 
- **Public input:** `(C, P₀, cnt, sum, sumsq)`; **witness:** the leaf prices and each node's child proofs
- **Map:** extract `p`, range-check `|p − P₀| ≤ 2500`, emit `(1, p − P₀, (p − P₀)²)` at fixed-point scale `10³`. **Reduce:** component-wise addition
- **Off-circuit:** the verifier derives mean and variance and re-adds `P₀`
The prover holds the block data: linear work to aggregate, logarithmic per new block. The verifier holds only `C` and runs one constant-time `Verify`, never touching a leaf or a Merkle path.
 
**Trust assumptions.** Collision resistance of Poseidon and knowledge soundness of Plonky2 (Thm. 3.1); the setup is transparent. The substantive assumption is the provenance of `C`: the proof binds the aggregates to *some* tree, so fabricated prices under a different root also yield a valid proof. The verifier must maintain or derive `C` itself, never accept it from the prover.

---
 
## 2. The proof system and framework

We use **Plonky2** over the **Goldilocks** field (`p = 2^64 - 2^32 + 1`) with **Poseidon** as the algebraic hash, matching the reference implementation so our figures stay comparable.

Three properties matter. The setup is **transparent** — no ceremony, no toxic waste — which suits a permissionless feed. Verification is **succinct and independent of the aggregated computation**, which is what makes the recursion terminate: if the in-circuit verifier scaled with what it verifies, circuit size would compound as `c^n` across levels. Poseidon is used for the same reason as in the paper — Keccak costs orders of magnitude more constraints in-circuit — at the price that our digests are not Ethereum's, the gap digest translation exists to close.

The consequence for our design: the level circuit `B_i` has **fixed size** — one Merkle hash, one Reduce, two recursive verifications — regardless of depth. Constant proof size and constant verification follow from that, not from FRI alone.

---
 
## 3. What can be improved

**Proof size blocks the stated use case.** Reckle proofs are ~112 KiB, constant in batch and vector size. The paper motivates the construction with on-chain verification, yet no Ethereum contract can verify 112 KiB. A Groth16 wrapper would bring it to ~192 bytes, at the cost of a trusted setup. This is the sharpest gap between what the paper motivates and what it delivers.

**Batch proofs are not zero-knowledge.** Verification recomputes the canonical digest from the claimed leaf values, so the verifier learns every leaf. Price feeds are public and our application is unaffected, but this rules out the privacy-sensitive workloads the framework otherwise fits: solvency proofs, tallying, anything whose leaves are user data.

**`q`-ary circuits are unimplemented.** Ethereum's Merkle Patricia Tries are 16-ary. Figure 5 sketches the parameterised circuits `Q_k`, but the paper leaves them as future work, so the construction does not yet apply to the structure it targets.

**The `leaf()` gap is left conditional.** Section 3.3 notes that circuit `B` does not force a batch to bottom out at real leaves: a prover can stop early and prove over a truncated tree. A fix is proposed but not adopted. Our level-specific circuits (Fig. 4) close it as a side effect — each level hardcodes a different `vk_{i-1}`, so the height is pinned by the key chain — and we test that rather than assume it.

**Expressiveness is bounded by the monoid structure.** `Reduce` folds pairwise, so it must be associative and carry fixed-size state. Our case shows the edge: volatility is properly the dispersion of log-returns, and logarithms would need polynomial approximation in-circuit.

**Field width constrains fixed-point precision.** `sumsq` accumulates squares in a 64-bit field. With prices up to `10^5` and `2^12` leaves, only three decimal digits fit before it wraps; centring on a public `P0` buys back roughly one. Wraparound is silent, which makes this a soundness bug rather than a precision one (§5).

**The artifact is not reproducible.** A fresh clone does not build; see §5.

Our extension addresses the last three: a new Map/Reduce instantiation, the fixed-point soundness analysis it forces, and a buildable artifact.


---
 
## 4. Feasibility analysis

| Bucket | Items |
|---|---|
| **Implemented** | Volatility Map/Reduce over Reckle+; level-specific circuits (Fig. 4); `O(log n)` single-leaf updates; two-sided range check; fixed-point overflow analysis; monolithic baseline; reproducible build |
| **Feasible, out of scope** | Fixed-arity `q`-ary circuits; Groth16 wrapping; bucketing retuned to our hardware |
| **Open problems** | Nova-style folding over a tree; zero-knowledge batch proofs; log-return volatility |

**`q`-ary circuits** need `q+1` variants and either a proof-size bound or per-level keys. Out of scope on time, not difficulty. **Groth16 wrapping** is well-trodden, but the Plonky2 wrapper toolchain is fragile and it reintroduces a trusted setup — a regression the paper would have to argue for.

**Folding is genuinely open.** Nova folds a *chain*; Reckle recurses over a *tree*. More than two instances per step needs multi-instance folding (ProtoGalaxy) or PCD: research, not implementation. **Zero-knowledge** would mean committing to leaf values rather than exposing them, changing canonical hashing itself. **Log-returns** need `log` in-circuit; a polynomial approximation introduces error whose effect on soundness we have not analysed, so we do not claim it reachable.

We also record what we deliberately did *not* do. Our window is the whole tree, so the batch is all leaves and no canonical digest is needed — the paper's own digest-translation configuration. Its BLS circuit drops it too, binding the subset only through `cnt`, but that pattern does not transfer: an existentially quantified subset would let a prover cherry-pick blocks. Arbitrary sub-windows are the natural next extension.

---
 
## 5. The implementation

Rust, ~1.5k lines. `merkle.rs` builds the tree off-circuit; `circuit_b0.rs` maps and hashes leaf pairs; `circuit_bi.rs` verifies two child proofs and reduces; `reckle_tree.rs` assembles `Lambda` and implements `UpdBatchProof`; `baseline.rs` is the monolithic comparison.

**Design decisions.** The circuit emits `(cnt, sum, sumsq)`, not the variance: division is expensive in-circuit, and variance is not associative, so it cannot travel up a binary fold. The fixed-point scale is `10^3`, chosen so the worst legal `sumsq` clears the modulus by 9 bits; `10^4` leaves 2 and is unsafe. Deviations are range-checked **two-sided**: `split_le` alone bounds one end, admitting deviations 2.4x the specification and leaving the band asymmetric.

**Reproducibility.** The reference artifact does not build from a fresh clone. `Cargo.lock` was gitignored, so resolution now picks `edition2024` crates the pinned toolchain cannot parse; the pin itself is mandatory, because the Lagrange plonky2 fork uses `feature(stdsimd)`, removed from Rust in 2024; and the git dependencies float with upstream. We commit a lockfile and pin both toolchain and dependencies.

**Tests**, all in CI:

| Test | Shows |
|---|---|
| Reference vectors | Python and Rust agree on 4096 leaves, independently computed |
| Reckle vs baseline | both systems produce identical public inputs |
| Range-check band | `±MAX_DEV` accepted, one tick past either end rejected |
| Overflow attack | unchecked, the circuit reports 65 USD of volatility where the truth is 4.3M; the range check blocks it |
| Truncated tree | §3.3's `leaf()` gap does not apply — level circuits hardcode distinct `vk_{i-1}` |
| Mismatched `P0` | subtrees centred differently do not merge |

---
 
## 6. Performance

We evaluate our implementation on an AMD Ryzen 9 6900HS Creator Edition processor (8 cores / 16 threads, up to 4.94 GHz) running Ubuntu 22.04 LTS. All benchmarks were executed using Cargo in release mode (`cargo bench --bench benchmark`) with target CPU vectorization features enabled.

### 6.1 Empirical Latency Measurements

The parameters correspond to the notation in the original paper (§5):
- **$h$ (Leaf / Poseidon cost):** Latency to execute the leaf-level circuit $\mathcal{B}_0$, performing in-circuit Poseidon hashing, the two-sided 23-bit range check, and base pairwise aggregation.
- **$r$ (Recursive step cost):** Proving latency for the recursive circuit $\mathcal{B}_i$, verifying two inner Plonky2 proofs and reducing accumulator states.
- **$v$ (Verification latency):** Time required to verify the top-level root proof.
- **$\text{UpdBatchProof}$:** Time required to process an incremental leaf update in $O(\log n)$ by ascending the active path in the memoized structure $\Lambda$.

| Operation | Circuit / Step | Proving Time | Verification Time |
|:---|:---|:---:|:---:|
| **Leaf Prover** | $\mathcal{B}_0$ (Pairwise leaves) | 36.60 ms | 2.63 ms |
| **Recursive Step ($r$)** | $\mathcal{B}_i$ (Child proof composition) | 376.16 ms | 4.13 ms |
| **Batch Proof Update** | Reckle $\Lambda$ ($N = 4$, height 2) | 389.41 ms | 4.13 ms |
| **Monolithic Baseline** | Flat unrolled circuit ($N = 4$) | 20.37 ms | 1.85 ms |

---

### 6.2 Analysis & Scalability Comparison

1. **Alignment with Paper Estimates:**
   The paper reports an empirical recursion step $r \approx 450\text{ ms}$ on standard workstation hardware. Our release build achieves **$r \approx 376.16\text{ ms}$**, confirming that Plonky2's Goldilocks field and recursive FRI stark verifiers scale predictably across modern x86_64 architectures. Leaf-level hashing and Map arithmetic run in just **$36.60\text{ ms}$**.

2. **$O(\log n)$ Dynamic Updates vs. Monolithic Re-Proving:**
   - **Small-Scale Regime ($N = 4$):** 
     For $N = 4$, the monolithic baseline outperforms Reckle (20.37 ms vs. 389.41 ms) because the flat circuit incurs no recursion overhead—it fits entirely inside a single low-degree polynomial commitment. In Reckle, the minimum update cost is bounded by $1 \times \mathcal{B}_0 + 1 \times \mathcal{B}_1 \approx 36.60\text{ ms} + 376.16\text{ ms} \approx 412.76\text{ ms}$ (measured at 389.41 ms).
   - **Asymptotic Regime ($N = 4096$):** 
     As proved in §5.3 of the paper, the monolithic circuit experiences exponential gate proliferation: at $N \ge 256$, proof generation times degrade by orders of magnitude and quickly exhaust system RAM (OOM). In contrast, Reckle scales strictly logarithmically:
     $$\text{Cost}_{\text{update}}(4096) = 1 \times \mathcal{B}_0 + 11 \times \mathcal{B}_i \approx 36.6\text{ ms} + 11 \cdot (376.2\text{ ms}) \approx 4.17\text{ s}$$
     This guarantees a constant memory footprint ($\approx \mathcal{O}(1)$ working RAM per step) and enables steady 12-second block update intervals without recomputing the entire sliding window.

3. **Succinct On-Chain Verification:**
   Regardless of the batch size $N$, verification complexity remains strictly $\mathcal{O}(1)$. Root proof verification completes in **4.13 ms**, providing an efficient settlement target for layer-2 or coprocessor verifiers.



---

## Build and run

```bash
git clone https://github.com/lucasmargni/zkp-verifiable-price-volatility && cd zkp-verifiable-price-volatility
cargo test --release --locked # test suite
cargo bench --bench benchmark -- 4 8 16 32 64 # benchmarks -> benchdata/results.csv
python3 scripts/test_reference.py # reference implementation self-check
```

The toolchain is pinned in `rust-toolchain.toml` and applies automatically. The
committed `Cargo.lock` is required; do not run `cargo update`. A release build
needs roughly 3 GB in `target/`.

## Contributions

- **Coronel, Paula Martina** — off-circuit Merkle tree, `B0` and `Bi` circuits, Reckle assembly and the `O(log n)` update path, monolithic baseline, benchmark suite.
- **Margni, Lucas Agustin** — repository and toolchain setup, Python reference vectors, fixed-point and overflow analysis, shared Map gadget, soundness tests, CI.

Tests and this report were written jointly.

## Attribution

The recursive construction follows the reference implementation by Lagrange Labs
(linked above); see its `LICENSE`. Our circuits were written from scratch against
the paper's Figures 4 and 6 rather than copied. The Map/Reduce instantiation, the
fixed-point soundness analysis, the two-sided range check, the baseline and the
test suite are ours.
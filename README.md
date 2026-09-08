# Verifiable Price Volatility over Reckle Trees
 
An updatable Map/Reduce instantiation of Reckle+ trees for on-chain volatility statistics.
 
**Course:** Building Cryptographic Proofs: ZKPs & SNARKs — 39th ECI, UBA
**Authors:** `Coronel, Paula Martina`, `Margni, Lucas Agustin`
**Base paper:** Papamanthou, Srinivasan, Gailly, Hishon-Rezaizadeh, Salumets, Golemac. *Reckle Trees: Updatable Merkle Batch Proofs with Applications.* ACM CCS 2024.
**Reference implementation:** https://github.com/Lagrange-Labs/reckle-trees

[![CI](https://github.com/lucasmargni/zkp-verifiable-price-volatility/actions/workflows/ci.yml/badge.svg)](https://github.com/lucasmargni/zkp-verifiable-price-volatility/actions/workflows/ci.yml)

---

## 1. The application

A Merkle batch proof over `|I|` arbitrary slots costs `O(|I| log n)` hashes and is not succinct. Reckle trees make it succinct via a recursive SNARK at each node, and keep it **updatable**: a leaf change refreshes the proof in time logarithmic in `n`. Reckle+ extends this from proving *contents* to proving *computation*, embedding a Map/Reduce pair in the recursive circuit. Among the DeFi workloads the paper lists but does not implement is price volatility over a sliding window. We implement it: our tree holds 4096 blocks of an ETH/USD feed, one per leaf (~13.6 h). We prove:
 
> `(cnt, sum, sumsq)` is the result of the Map/Reduce computation over **all** leaves of the Merkle tree with root `C`.
 
- **Public input:** `(C, P₀, cnt, sum, sumsq)`; **witness:** the leaf prices and each node's child proofs
- **Map:** extract `p`, range-check `|p − P₀| ≤ 2500`, emit `(1, p − P₀, (p − P₀)²)` at fixed-point scale `10³`. **Reduce:** component-wise addition
- **Off-circuit:** the verifier derives mean and variance and re-adds `P₀`

The prover holds the block data: linear work to aggregate, logarithmic per block. The verifier holds only `C` and runs one constant-time `Verify`.
 
**Trust assumptions.** Collision resistance of Poseidon and knowledge soundness of Plonky2 (Thm. 3.1); the setup is transparent. The substantive assumption is the provenance of `C`: the proof binds the aggregates to *some* tree, so fabricated prices under another root also verify. The verifier must derive `C` itself, never accept it from the prover.

---
 
## 2. The proof system and framework

We use **Plonky2** over **Goldilocks** (`p = 2^64 - 2^32 + 1`) with **Poseidon**, matching the reference implementation so our figures stay comparable.

Three properties matter. The setup is **transparent**, suiting a permissionless feed. Verification is **succinct and independent of the aggregated computation**, which is what makes the recursion terminate: were the in-circuit verifier to scale with what it verifies, circuit size would compound as `c^n` across levels. Poseidon is used for the paper's reason — Keccak costs orders of magnitude more constraints in-circuit — at the price that our digests are not Ethereum's, the gap digest translation exists to close.

The consequence: the level circuit `B_i` has **fixed size** — one Merkle hash, one Reduce, two recursive verifications — regardless of depth. Constant proof size and verification follow from that, not from FRI alone.

---
 
## 3. What can be improved

**Proof size blocks the stated use case.** Reckle proofs are ~112 KiB, constant in batch and vector size, yet no Ethereum contract can verify 112 KiB. A Groth16 wrapper would bring it to ~192 bytes, at the cost of a trusted setup. This is the sharpest gap between what the paper motivates and what it delivers.

**Batch proofs are not zero-knowledge.** Verification recomputes the canonical digest from the claimed leaf values, so the verifier learns every leaf. Price feeds are public, so we are unaffected, but this rules out privacy-sensitive workloads: solvency proofs, tallying, any leaves that are user data.

**`q`-ary circuits are unimplemented.** Ethereum's Merkle Patricia Tries are 16-ary. Figure 5 sketches the circuits `Q_k` but leaves them as future work, so the construction does not yet apply to its target structure.

**The `leaf()` gap is left conditional.** Section 3.3 notes that circuit `B` does not force a batch to bottom out at real leaves: a prover can stop early and prove over a truncated tree. The proposed fix is not adopted. Our level circuits (Fig. 4) close it as a side effect — each hardcodes a different `vk_{i-1}`, pinning the height — and we test that.

**Expressiveness is bounded by the monoid structure.** `Reduce` folds pairwise, so it must be associative with fixed-size state. Our case shows the edge: volatility is properly the dispersion of log-returns, and logarithms need polynomial approximation in-circuit.

**Field width constrains fixed-point precision.** `sumsq` accumulates squares in a 64-bit field: with prices up to `10^5` and `2^12` leaves only three decimal digits fit before it wraps, and centring on `P0` buys back roughly one. Wraparound is silent, making this a soundness bug, not a precision one (§5).

**The artifact is not reproducible** from a fresh clone; see §5.

Our extension takes on the last two, plus a Map/Reduce instantiation that runs up against the monoid constraint.


---
 
## 4. Feasibility analysis

| Bucket | Items |
|---|---|
| **Implemented** | Volatility Map/Reduce over Reckle+; level-specific circuits (Fig. 4); `O(log n)` single-leaf updates; two-sided range check; fixed-point overflow analysis; monolithic baseline; reproducible build |
| **Feasible, out of scope** | Fixed-arity `q`-ary circuits; Groth16 wrapping; bucketing retuned to our hardware |
| **Open problems** | Nova-style folding over a tree; zero-knowledge batch proofs; log-return volatility |

**`q`-ary circuits** need `q+1` variants and either a proof-size bound or per-level keys: out of scope on time, not difficulty. **Groth16 wrapping** is well-trodden, but the Plonky2 wrapper toolchain is fragile and it reintroduces a trusted setup.

**Folding is genuinely open.** Nova folds a *chain*; Reckle recurses over a *tree*. More than two instances per step needs multi-instance folding (ProtoGalaxy) or PCD: research, not implementation. **Zero-knowledge** would mean committing to leaf values instead of exposing them, changing canonical hashing itself. **Log-returns** need `log` in-circuit; a polynomial approximation introduces error whose soundness effect we have not analysed.

We also record what we did *not* do. Our window is the whole tree, so no canonical digest is needed — the paper's own digest-translation configuration. Its BLS circuit drops it too, binding the subset through `cnt` alone, but that does not transfer: an existential subset would let a prover cherry-pick blocks. Arbitrary sub-windows are the next extension.

---
 
## 5. The implementation

Rust on Plonky2, ~1.5k lines, chosen for comparability with the reference implementation. `merkle.rs` builds the tree off-circuit; `circuit_b0.rs` maps and hashes leaf pairs; `circuit_bi.rs` verifies two child proofs and reduces; `reckle_tree.rs` assembles `Lambda` and `UpdBatchProof`; `baseline.rs` is the comparison. One deviation from plan: canonical hashing was dropped once the window became the whole tree (§4).

**Design decisions.** The circuit emits `(cnt, sum, sumsq)`, not the variance: division is costly in-circuit, and variance is not associative, so it cannot travel up a binary fold. The fixed-point scale is `10^3`, so the worst legal `sumsq` clears the modulus by 9 bits; `10^4` leaves 2 and is unsafe. Range checks are **two-sided**: `split_le` alone bounds one end, admitting deviations 2.4x the specification.

**Reproducibility.** The reference artifact does not build from a fresh clone: `Cargo.lock` was gitignored, so resolution picks `edition2024` crates the pinned toolchain cannot parse; the pin is mandatory, since the Lagrange plonky2 fork uses `feature(stdsimd)`, removed from Rust in 2024; and its git dependencies float with upstream. We commit a lockfile and pin both.

**Tests**, all in CI:

| Test | Shows |
|---|---|
| Reference vectors | Python and Rust agree on 4096 leaves, computed independently |
| Reckle vs baseline | both produce identical public inputs |
| Range-check band | `±MAX_DEV` accepted, one tick past either end rejected |
| Overflow attack | unchecked, the circuit reports 65 USD of volatility; truth is 4.3M |
| Truncated tree | §3.3's `leaf()` gap does not apply |
| Mismatched `P0` | subtrees centred differently do not merge |

---
 
## 6. Performance

AMD Ryzen 9 6900HS (8c/16t), 28 GiB RAM, Ubuntu 24.04, release build. Sweep `n = 4..256`; per-step costs `h = 67.7 ms`, `r = 636.8 ms` (paper: 450 ms).

Each cell is Reckle / baseline.

| `n` | aggregate | update | proof |
|---:|---|---|---|
| 16 | 5.51 s / 0.032 s | 1.87 s / 0.027 s | 129.8 / 91.9 KiB |
| 64 | 21.14 s / 0.052 s | 3.52 s / 0.046 s | 129.8 / 101.0 KiB |
| 256 | 79.23 s / 0.172 s | 5.02 s / 0.181 s | 129.8 / 118.7 KiB |

**Reckle loses at every size we measured** — 28-76x slower on updates, 62-461x on aggregation. Generating `n-1` recursive proofs where the baseline generates one is not recovered at this scale.

**Proof size is the clear win.** Flat at 129.8 KiB from `n = 8` (paper: 112 KiB), against a baseline growing 76 to 119 KiB — sub-logarithmic, not linear: 1.56x for 64x the leaves, as Plonky2 proof size tracks the log of circuit size. Verification is ~4 ms for both, flat.

**The baseline does not exhaust memory**, contrary to what we expected from §5.3: a monolithic circuit over 511 Poseidon hashes reproves in 0.18 s. The paper's baselines are Groth16 aggregation and Hyperproofs, not this.

**Crossover.** Baseline reproof is linear (0.70 ms/leaf), Reckle's update logarithmic (0.79 s/level). Extrapolated they cross at `n ~ 14,500` — past our 4,096 window, where Reckle needs ~8.7 s against the baseline's ~2.9 s. The asymptotic advantage is real but begins beyond our target workload. `Lambda` stores all `n-1` proofs (~519 MiB at 4,096): memory is constant per step, linear overall.

**Soundness has a price.** The two-sided range check raised `h` 1.85x and `r` 1.69x.

---

## Build and run

```bash
git clone https://github.com/lucasmargni/zkp-verifiable-price-volatility && cd zkp-verifiable-price-volatility
cargo test --release --locked          # test suite
cargo bench --bench benchmark -- 4 8 16 32 64   # benchmarks -> benchdata/results.csv
python3 scripts/test_reference.py      # reference implementation self-check
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
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
The prover holds the block data: linear work to aggregate, logarithmic per new block. The verifier holds only `C` and runs one constant-time `Verify`, never touching a leaf or a Merkle path. This is the paper's own scenario: an options protocol repricing every 12 seconds.
 
**Trust assumptions.** Collision resistance of Poseidon and knowledge soundness of Plonky2 (Thm. 3.1); the setup is transparent. `P₀` is public and untrusted, it only shifts the encoding. The substantive assumption is the provenance of `C`: the proof binds the aggregates to *some* tree, so fabricated prices under a different root also yield a valid proof. The verifier must maintain or derive `C` itself, never accept it from the prover.

---
 
## 2. The proof system and framework



---
 
## 3. What can be improved

**Proof size blocks the stated use case.** Reckle proofs are ~112 KiB, constant in both batch and vector size. The paper motivates the construction with on-chain verification, yet no Ethereum contract can verify 112 KiB. Wrapping the root proof in Groth16 would bring it to ~192 bytes, at the cost of a trusted setup and a pairing-friendly curve. This is the sharpest gap between what the paper motivates and what it delivers.

**Batch proofs are not zero-knowledge.** Verification recomputes the canonical digest from the claimed leaf values, so the verifier learns every leaf. Price feeds are public and our application is unaffected, but this rules out the privacy-sensitive workloads the framework otherwise fits: solvency proofs, tallying, anything whose leaves are user data.

**`q`-ary circuits are unimplemented.** Ethereum's Merkle Patricia Tries are 16-ary. Figure 5 sketches the parameterised circuits `Q_k`, but the paper leaves them as future work, so the construction does not yet apply to the structure it targets.

**The `leaf()` gap is left conditional.** Section 3.3 notes that circuit `B` does not force a batch to bottom out at real leaves: a prover can stop early and prove over a truncated tree. A fix is proposed but not adopted. Our level-specific circuits (Fig. 4) close it as a side effect — each level hardcodes a different `vk_{i-1}`, so the height is pinned by the key chain — and we test that rather than assume it.

**Expressiveness is bounded by the monoid structure.** `Reduce` folds pairwise over a binary tree, so it must be associative and carry fixed-size state. Our case shows the edge: financial volatility is properly the dispersion of log-returns, and logarithms would need polynomial approximation in-circuit.

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

**`q`-ary circuits** are feasible in principle but need `q+1` circuit variants and either a proof-size bound or per-level hardcoded keys. Out of scope on time, not on difficulty.

**Groth16 wrapping** is well-trodden engineering, but the Plonky2 wrapper toolchain is fragile and it reintroduces a trusted setup — a design regression the paper would have to argue for.

**Folding is genuinely open.** Nova folds a *chain* of instances; Reckle recurses over a *tree*. Combining more than two instances per step needs multi-instance folding (ProtoGalaxy) or PCD. We classify this as research, not implementation.

**Zero-knowledge** would require committing to leaf values rather than exposing them, which changes canonical hashing itself. Also open.

**Log-returns** need `log` in-circuit. A polynomial approximation would introduce error whose effect on soundness we have not analysed, so we do not claim it as reachable.

We also record what we deliberately did *not* do. Our window is the whole tree, so the batch is all leaves and no canonical digest is needed — the configuration the paper uses for digest translation. Note that the BLS circuit also drops it, binding the subset only through `cnt`; that pattern does not transfer to volatility, where an existentially quantified subset would let a prover cherry-pick blocks. Supporting arbitrary sub-windows (canonical digest plus an index-range check) is the natural next extension.

---
 
## 5. The implementation



---
 
## 6. Performance



---

## Authors

- `Coronel, Paula Martina`
- `Margni, Lucas Agustin`

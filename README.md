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



---
 
## 4. Feasibility analysis



---
 
## 5. The implementation



---
 
## 6. Performance



---

## Authors

- `Coronel, Paula Martina`
- `Margni, Lucas Agustin`

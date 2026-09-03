#!/usr/bin/env python3
"""
Reference implementation for the volatility Map/Reduce aggregates.

Deliberately independent of the circuit: plain Python integers, no field
arithmetic tricks, no Plonky2. The Rust tests check the circuit against these
vectors, so a bug in the circuit cannot cancel out against a bug in the test.

Scope note: this does NOT cover Poseidon. Merkle-hash correctness is checked
separately against Plonky2's own known-answer vectors (see tests/poseidon_kat.rs).
What is covered here is the arithmetic, which is where the fixed-point and
overflow bugs live.
"""

import json
from pathlib import Path

P = 2**64 - 2**32 + 1        # Goldilocks
SCALE = 10**3                # fixed-point: 3 decimal digits
D = 2_500 * SCALE            # max deviation from P0, encoded  (= 2_500_000)
WINDOW = 4096                # leaves per tree


def encode(price_usd: float) -> int:
    """USD price -> field-encoded fixed-point integer."""
    return round(price_usd * SCALE)


def map_leaf(price_enc: int, p0_enc: int) -> tuple[int, int, int]:
    """Map: one leaf -> (cnt, delta, delta^2). Raises if out of range."""
    delta = price_enc - p0_enc
    if not (-D <= delta <= D):
        raise ValueError(f"deviation {delta} outside +/-{D}")
    return (1, delta, delta * delta)


def reduce_pair(a: tuple[int, int, int], b: tuple[int, int, int]) -> tuple[int, int, int]:
    """Reduce: component-wise addition. Associative, fixed-size."""
    return (a[0] + b[0], a[1] + b[1], a[2] + b[2])


def aggregate(prices_enc: list[int], p0_enc: int) -> tuple[int, int, int]:
    """Fold the whole window the way the recursive circuit does: bottom-up, pairwise."""
    level = [map_leaf(p, p0_enc) for p in prices_enc]
    while len(level) > 1:
        level = [reduce_pair(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def to_field(x: int) -> int:
    """Lift a signed integer into Goldilocks, the way the circuit represents it."""
    return x % P


def from_field(x: int) -> int:
    """Inverse: interpret a field element as signed. Unambiguous while |x| < P/2."""
    return x - P if x > P // 2 else x


def stats(cnt: int, sum_: int, sumsq: int, p0_enc: int) -> dict:
    """What the verifier computes off-circuit, in USD."""
    mean_enc = p0_enc + sum_ / cnt
    var_enc = sumsq / cnt - (sum_ / cnt) ** 2
    return {
        "mean_usd": mean_enc / SCALE,
        "variance_usd2": var_enc / SCALE**2,
        "stddev_usd": var_enc**0.5 / SCALE,
    }


def headroom_bits(sumsq: int) -> float:
    """How far the worst-case sumsq sits below the field modulus."""
    return P.bit_length() - max(sumsq, 1).bit_length()


def synth_prices(n: int, base: float, amp: float) -> list[float]:
    """Deterministic pseudo-random walk. No RNG dependency, so vectors are stable."""
    out, x, s = [], base, 12345
    for _ in range(n):
        s = (1103515245 * s + 12345) % (2**31)
        x += ((s / 2**31) - 0.5) * amp
        out.append(round(x, 3))
    return out


def build_case(name: str, prices_usd: list[float], p0_usd: float,
               should_reject: bool, why: str) -> dict:
    p0_enc = encode(p0_usd)
    prices_enc = [encode(p) for p in prices_usd]
    case = {
        "name": name,
        "should_reject": should_reject,
        "reason": why,
        "p0_enc": p0_enc,
        "n_leaves": len(prices_enc),
        "prices_enc": prices_enc,
    }
    try:
        cnt, sum_, sumsq = aggregate(prices_enc, p0_enc)
    except ValueError as e:
        case["expected"] = None
        case["rejected_by_reference"] = str(e)
        return case
    case["expected"] = {
        "cnt": cnt,
        "sum_signed": sum_,
        "sum_field": to_field(sum_),
        "sumsq": sumsq,
        "sumsq_field": to_field(sumsq),
        "headroom_bits": round(headroom_bits(sumsq), 1),
        **{k: round(v, 6) for k, v in stats(cnt, sum_, sumsq, p0_enc).items()},
    }
    return case


def main() -> None:
    cases = []

    # 1. tiny tree, hand-checkable
    cases.append(build_case(
        "tiny_4", [3000.0, 3000.5, 2999.25, 3001.0], 3000.0,
        False, "smallest tree that still exercises two Reduce levels"))

    # 2. every leaf equals P0 -> sum and variance must be exactly zero
    cases.append(build_case(
        "all_equal_16", [3000.0] * 16, 3000.0,
        False, "degenerate: zero variance, catches sign and rounding bugs"))

    # 3. full window
    cases.append(build_case(
        "window_4096", synth_prices(WINDOW, 3000.0, 4.0), 3000.0,
        False, "realistic full-size window"))

    # 4. worst case still inside the range check
    cases.append(build_case(
        "boundary_max_dev", [3000.0 + 2500.0, 3000.0 - 2500.0] * (WINDOW // 2), 3000.0,
        False, "every leaf at the range-check boundary; maximal legal sumsq"))

    # 5. one leaf just over the bound -> must be rejected
    over = [3000.0] * WINDOW
    over[7] = 3000.0 + 2500.001
    cases.append(build_case(
        "reject_out_of_range", over, 3000.0,
        True, "one deviation exceeds D by one tick; range check must reject"))

    # 6. the overflow attack: deviations large enough to wrap sumsq mod P
    #    (only reachable if the range check is missing)
    big = int((P // WINDOW) ** 0.5) + 1        # smallest delta whose square*WINDOW exceeds P
    attack_price = (encode(3000.0) + big) / SCALE
    cases.append(build_case(
        "reject_overflow_attack", [attack_price] * WINDOW, 3000.0,
        True, "crafted deviations wrap sumsq mod P; without range checks a false variance verifies"))

    out = {
        "params": {
            "field_modulus": P,
            "scale": SCALE,
            "max_deviation_enc": D,
            "range_check_bits": (2 * D).bit_length(),
            "window": WINDOW,
        },
        "cases": cases,
    }
    dest = Path(__file__).resolve().parents[1] / "testdata" / "vectors.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(out, indent=2) + "\n")

    print(f"wrote {dest}")
    print(f"range check needs {out['params']['range_check_bits']} bits\n")
    for c in cases:
        if c["expected"]:
            e = c["expected"]
            print(f"  {c['name']:24s} n={c['n_leaves']:5d}  sumsq={e['sumsq']:>22d}  "
                  f"headroom={e['headroom_bits']:>5} bits  sd={e['stddev_usd']:.4f} USD")
        else:
            print(f"  {c['name']:24s} n={c['n_leaves']:5d}  REJECTED: {c['rejected_by_reference']}")


if __name__ == "__main__":
    main()

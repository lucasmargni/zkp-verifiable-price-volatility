#!/usr/bin/env python3
"""
Sanity checks for the reference implementation itself.

The Rust tests trust gen_vectors.py as the source of truth, so that file needs
its own independent check. Everything here is computed a second way — flat sums,
the statistics module, explicit modular arithmetic — never by reusing the
aggregate() fold under test.
"""

import statistics
import sys

sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent))
from gen_vectors import (P, SCALE, D, WINDOW, aggregate, encode, map_leaf,
                         reduce_pair, from_field, to_field, synth_prices, stats)

fails = []


def check(name, cond, detail=""):
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  [{detail}]" if detail else ""))
    if not cond:
        fails.append(name)


print("1. Reduce is associative (required: the fold runs over a binary tree)")
a, b, c = (1, 5, 25), (1, -3, 9), (1, 7, 49)
check("(a+b)+c == a+(b+c)",
      reduce_pair(reduce_pair(a, b), c) == reduce_pair(a, reduce_pair(b, c)))

print("\n2. Tree fold equals a flat sum (computed independently)")
prices = [encode(p) for p in synth_prices(1024, 3000.0, 4.0)]
p0 = encode(3000.0)
cnt, sum_, sumsq = aggregate(prices, p0)
flat_deltas = [x - p0 for x in prices]
check("cnt", cnt == len(prices), f"{cnt}")
check("sum", sum_ == sum(flat_deltas), f"{sum_}")
check("sumsq", sumsq == sum(d * d for d in flat_deltas), f"{sumsq}")

print("\n3. Variance matches Python's statistics module")
ours = stats(cnt, sum_, sumsq, p0)["variance_usd2"]
theirs = statistics.pvariance([x / SCALE for x in prices])
check("population variance agrees", abs(ours - theirs) < 1e-6,
      f"ours={ours:.6f} statistics={theirs:.6f}")

print("\n4. Degenerate case: all leaves equal P0 -> exact zeros")
cnt0, s0, sq0 = aggregate([p0] * 16, p0)
check("sum == 0 exactly", s0 == 0)
check("sumsq == 0 exactly", sq0 == 0)

print("\n5. Signed field encoding round-trips")
for v in (0, 1, -1, D, -D, sum_, -sum_):
    check(f"round-trip {v}", from_field(to_field(v)) == v)

print("\n6. Range check boundary is exactly where we claim")
try:
    map_leaf(p0 + D, p0); ok_in = True
except ValueError:
    ok_in = False
try:
    map_leaf(p0 + D + 1, p0); ok_out = False
except ValueError:
    ok_out = True
check("D accepted", ok_in)
check("D+1 rejected", ok_out)

print("\n7. Worst legal case fits under the modulus")
worst = WINDOW * D * D
check("worst-case sumsq < P", worst < P,
      f"headroom {P.bit_length() - worst.bit_length()} bits")

print("\n8. The overflow attack is real (this is what the range check prevents)")
big = int((P // WINDOW) ** 0.5) + 1
true_sumsq = WINDOW * big * big
wrapped = true_sumsq % P
check("true sumsq exceeds P", true_sumsq > P)
check("wrapping changes the value", wrapped != true_sumsq)
check("wrapped value looks small and innocent", wrapped < true_sumsq)
print(f"        true    = {true_sumsq}")
print(f"        mod P   = {wrapped}   <- what an unchecked circuit would output")
print(f"        implied stddev = {(wrapped / WINDOW) ** 0.5 / SCALE:.2f} USD "
      f"(real: {(true_sumsq / WINDOW) ** 0.5 / SCALE:.2f} USD)")

print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)

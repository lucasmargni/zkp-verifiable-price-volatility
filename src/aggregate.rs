//! Out-of-circuit aggregation: folds a window of leaves the way the recursive
//! circuit does, pairwise and bottom-up. Used as the expected value in tests
//! and as the monolithic baseline's inner computation.

use crate::{map_leaf, reduce, Acc, OutOfRange};

/// Fold a whole window. Mirrors the tree shape rather than summing flat, so a
/// grouping bug in the circuit shows up here too.
pub fn aggregate(prices_enc: &[u64], p0_enc: u64) -> Result<Acc, OutOfRange> {
    assert!(!prices_enc.is_empty(), "empty window");
    assert!(prices_enc.len().is_power_of_two(), "window must be a power of two");

    let mut level: Vec<Acc> = prices_enc
        .iter()
        .map(|&p| map_leaf(p, p0_enc))
        .collect::<Result<_, _>>()?;

    while level.len() > 1 {
        level = level.chunks_exact(2).map(|c| reduce(c[0], c[1])).collect();
    }
    Ok(level[0])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{encode, from_field, stats};

    #[test]
    fn hand_checkable_tiny_tree() {
        // deviations: 0, +500, -750, +1000  =>  sum 750, sumsq 1_812_500
        let p0 = encode(3000.0);
        let prices: Vec<u64> = [3000.0, 3000.5, 2999.25, 3001.0].iter().map(|&p| encode(p)).collect();
        let acc = aggregate(&prices, p0).expect("all leaves in range");
        assert_eq!(acc.cnt, 4);
        assert_eq!(from_field(acc.sum), 750);
        assert_eq!(acc.sumsq, 1_812_500);
    }

    #[test]
    fn all_leaves_equal_to_p0_gives_exact_zeros() {
        let p0 = encode(3000.0);
        let acc = aggregate(&vec![p0; 16], p0).unwrap();
        assert_eq!(from_field(acc.sum), 0);
        assert_eq!(acc.sumsq, 0);
        assert_eq!(stats(acc, p0).variance_usd2, 0.0);
    }

    #[test]
    fn one_out_of_range_leaf_rejects_the_whole_window() {
        let p0 = encode(3000.0);
        let mut prices = vec![p0; 16];
        prices[7] = p0 + crate::MAX_DEV + 1;
        assert!(aggregate(&prices, p0).is_err());
    }
}

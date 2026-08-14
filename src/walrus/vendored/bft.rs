// Copyright (c) Walrus Foundation
// SPDX-License-Identifier: Apache-2.0
//
// Vendored from walrus-core `src/bft.rs`
// Upstream: https://github.com/MystenLabs/walrus
// Commit:   14641cc0edcc727825d07aa19df2eef8046a3c0d
//
// Modifications Copyright Frank V. Castellucci:
//   * Only `max_n_faulty` and `min_n_correct` are vendored.
//   * Upstream `#[cfg(test)]` code omitted.

//! Definitions and computations related to Byzantine fault tolerance (BFT).

use core::num::NonZeroU16;

/// Returns the maximum number of faulty/Byzantine failures in a BFT system with `n` components.
///
/// This number is often called `f` and must be strictly less than `n as f64 / 3.0`.
#[inline]
pub fn max_n_faulty(n: NonZeroU16) -> u16 {
    (n.get() - 1) / 3
}

/// Returns the minimum number of correct (non-faulty) instances in a BFT system with `n`
/// components.
///
/// If `n == 3f + 1`, then this is equal to `2f + 1`. In other cases, this can be slightly higher.
#[inline]
pub fn min_n_correct(n: NonZeroU16) -> NonZeroU16 {
    (n.get() - max_n_faulty(n))
        .try_into()
        .expect("max_n_faulty < n")
}

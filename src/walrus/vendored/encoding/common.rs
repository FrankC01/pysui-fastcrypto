// Copyright (c) Walrus Foundation
// SPDX-License-Identifier: Apache-2.0
//
// Vendored from walrus-core `src/encoding/common.rs`
// Upstream: https://github.com/MystenLabs/walrus
// Commit:   14641cc0edcc727825d07aa19df2eef8046a3c0d
//
// Modifications Copyright Frank V. Castellucci:
//   * Encode and decode paths. `EncodingAxis` is a trait bound on the decode
//     types (`BlobDecoder`, `DecodingSymbol`) as well as the encode ones.
//   * `EncodingAxis::sliver_type()` omitted (unused on the encode path; its
//     removal drops the dependency on `SliverType` / `by_axis::Axis`).
//   * Upstream `#[cfg(test)]` code omitted.

//! Encoding axis marker types, vendored from walrus-core.

use serde::{Deserialize, Serialize};

/// Marker trait to indicate the encoding axis (primary or secondary).
pub trait EncodingAxis:
    Clone + PartialEq + Eq + Default + core::fmt::Debug + Send + Sync + 'static
{
    /// The complementary encoding axis.
    type OrthogonalAxis: EncodingAxis;
    /// Whether this corresponds to the primary (true) or secondary (false) encoding.
    const IS_PRIMARY: bool;
    /// String representation of this type.
    const NAME: &'static str;
}

/// Marker type to indicate the primary encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Primary;
impl EncodingAxis for Primary {
    type OrthogonalAxis = Secondary;
    const IS_PRIMARY: bool = true;
    const NAME: &'static str = "primary";
}

/// Marker type to indicate the secondary encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Secondary;
impl EncodingAxis for Secondary {
    type OrthogonalAxis = Primary;
    const IS_PRIMARY: bool = false;
    const NAME: &'static str = "secondary";
}

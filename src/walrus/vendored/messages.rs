// Copyright (c) Walrus Foundation
// SPDX-License-Identifier: Apache-2.0
//
// Vendored from walrus-core `src/messages.rs`
// Upstream: https://github.com/MystenLabs/walrus
// Commit:   14641cc0edcc727825d07aa19df2eef8046a3c0d
//
// Modifications Copyright Frank V. Castellucci:
//   * Only the storage-confirmation message path is vendored. `SignedMessage`,
//     `MessageVerificationError`, proof-of-possession, invalid-blob-id,
//     sync-shard and certificate submodules are omitted; signature
//     verification and aggregation live in this crate's own `walrus::bls`.
//   * `impl<T> ProtocolMessage<T>` accessors (`epoch`, `contents`) are omitted;
//     nothing in the encode/confirmation path calls them.
//   * `InvalidIntent` is vendored because `Confirmation`'s
//     `#[serde(try_from = ...)]` attribute requires the `TryFrom` impl that
//     returns it. The manifest did not list it; see the handoff.
//   * Upstream is `#![no_std]` and imports from `alloc`; this crate is std,
//     so those imports are dropped.
//   * Upstream `#[cfg(test)]` code omitted.

//! Signed-message types for Walrus storage confirmations, vendored from
//! walrus-core.

use serde::{Deserialize, Serialize};

use crate::walrus::vendored::core::Epoch;
use crate::walrus::vendored::utils::wrapped_uint;

mod storage_confirmation;
pub use storage_confirmation::{BlobPersistenceType, Confirmation, StorageConfirmationBody};

/// Message format for messages sent to the System Contracts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtocolMessage<T> {
    intent: Intent,
    /// The epoch in which this message is generated.
    epoch: Epoch,
    message_contents: T,
}

/// Error for invalid intents.
#[derive(Debug, thiserror::Error)]
#[error("expected intent ({expected:?}) does not match that of the message: {actual:?}")]
pub struct InvalidIntent {
    expected: Intent,
    actual: Intent,
}

// Make sure to update the list of intents in `contracts/walrus/docs/msg_formats.txt`
// as well. And keep the order and the indexes consistent with Move definitions in
// `contracts/walrus/sources/system/messages.move`.
wrapped_uint! {
    /// Type for the intent type of signed messages.
    pub struct IntentType(pub u8) {
        /// Intent type for proof of possession messages.
        pub const PROOF_OF_POSSESSION_MSG: Self = Self(0);
        /// Intent type for blob-certification messages.
        pub const BLOB_CERT_MSG: Self = Self(1);
        /// Intent type for invalid blob id messages.
        pub const INVALID_BLOB_ID_MSG: Self = Self(2);
        /// Intent type for invalid blob id messages.
        /// Note that this message is only used for communication between storage nodes.
        pub const SYNC_SHARD_MSG: Self = Self(3);
        /// Intent type for deny list update messages.
        pub const DENY_LIST_UPDATE_MSG: Self = Self(4);
        /// Intent type for deny list blob deleted messages.
        pub const DENY_LIST_BLOB_DELETED_MSG: Self = Self(5);
        /// Intent type for protocol version messages.
        pub const PROTOCOL_VERSION_MSG: Self = Self(6);
    }
}

wrapped_uint! {
    /// Type for the intent version of signed messages.
    #[derive(Default)]
    pub struct IntentVersion(pub u8) {
        /// Intent type for storage-certification messages.
        pub const DEFAULT: Self = Self(0);
    }
}

wrapped_uint! {
    /// Type used to identify the app associated with a signed message.
    pub struct IntentAppId(pub u8) {
        /// Walrus App ID.
        pub const STORAGE: Self = Self(3);
    }
}

/// Message intent prepended to signed messages.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Intent {
    /// The intent of the signed message.
    pub r#type: IntentType,
    /// The intent version.
    pub version: IntentVersion,
    /// The app ID, usually [`IntentAppId::STORAGE`] for Walrus messages.
    pub app_id: IntentAppId,
}

impl Intent {
    /// Creates a new intent with [`IntentAppId::STORAGE`] for the specified [`IntentType`].
    pub const fn storage(r#type: IntentType) -> Self {
        Self {
            r#type,
            version: IntentVersion::DEFAULT,
            app_id: IntentAppId::STORAGE,
        }
    }
}

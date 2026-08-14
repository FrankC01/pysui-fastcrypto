// Copyright (c) Walrus Foundation
// SPDX-License-Identifier: Apache-2.0
//
// Vendored from walrus-core `src/messages/storage_confirmation.rs`
// Upstream: https://github.com/MystenLabs/walrus
// Commit:   14641cc0edcc727825d07aa19df2eef8046a3c0d
//
// Modifications Copyright Frank V. Castellucci:
//   * Only the `Confirmation` construction path is vendored.
//     `StorageConfirmation`, `SignedStorageConfirmation`, its `verify` impl,
//     and `AsRef<ProtocolMessage<_>> for Confirmation` are omitted.
//   * Upstream is `#![no_std]` and imports from `alloc`; this crate is std,
//     so those imports are dropped.
//   * Upstream `#[cfg(test)]` code omitted. NOTE: upstream's tests at
//     117-171 assert the exact signed-byte layout and are the reference for
//     this crate's correctness gate B.

//! Storage-confirmation message body, vendored from walrus-core.

use serde::{Deserialize, Serialize};

use super::{Intent, IntentType, InvalidIntent, ProtocolMessage};
use crate::walrus::vendored::core::{BlobId, Epoch, SuiObjectId};

/// Indicates the persistence of a blob.
///
/// For deletable blobs the object ID of the associated Sui object is included.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlobPersistenceType {
    /// The blob is permanent.
    Permanent,
    /// The blob is deletable and has the given object ID.
    Deletable {
        /// The object ID of the associated Sui object.
        object_id: SuiObjectId,
    },
}

/// The message body for a [`Confirmation`],
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageConfirmationBody {
    /// The blob id of the blob that is being confirmed.
    pub blob_id: BlobId,
    /// Whether the blob is permanent or deletable.
    /// For deletable blobs, the object id of the blob is included.
    pub blob_type: BlobPersistenceType,
}

/// A Confirmation that a storage node has stored all respective slivers
/// of a blob in their shards.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
#[serde(try_from = "ProtocolMessage<StorageConfirmationBody>")]
pub struct Confirmation(pub(crate) ProtocolMessage<StorageConfirmationBody>);

impl Confirmation {
    const INTENT: Intent = Intent::storage(IntentType::BLOB_CERT_MSG);

    /// Creates a new confirmation message for the provided blob ID.
    pub fn new(epoch: Epoch, blob_id: BlobId, blob_type: BlobPersistenceType) -> Self {
        let message_contents = StorageConfirmationBody { blob_id, blob_type };
        Self(ProtocolMessage {
            intent: Intent::storage(IntentType::BLOB_CERT_MSG),
            epoch,
            message_contents,
        })
    }
}

impl TryFrom<ProtocolMessage<StorageConfirmationBody>> for Confirmation {
    type Error = InvalidIntent;
    fn try_from(
        protocol_message: ProtocolMessage<StorageConfirmationBody>,
    ) -> Result<Self, Self::Error> {
        if protocol_message.intent == Self::INTENT {
            Ok(Self(protocol_message))
        } else {
            Err(InvalidIntent {
                expected: Self::INTENT,
                actual: protocol_message.intent,
            })
        }
    }
}

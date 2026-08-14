//    Copyright Frank V. Castellucci
//    SPDX-License-Identifier: Apache-2.0

//! BLS12-381 (`min_pk`) signature verification and aggregation.
//!
//! Thin wrappers over `fastcrypto`, including conversion of the 96-byte
//! uncompressed G1 committee public keys stored on chain into the 48-byte
//! compressed form `fastcrypto` expects.

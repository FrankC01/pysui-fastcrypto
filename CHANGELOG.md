# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.3] - Unpublished

### Added

- `keys_from_mnemonics` takes phrase and derivation path

### Fixed

### Changed

- `keys_from_keystring` and `generate_new_keypair` now return private key bytess instead of token

### Removed

- Returning the SignatureScheme from `generate_new_keypair` and `keys_from_mnemonics`
- Returning the mnemonic phrase from `keys_from_mnemonics

## [0.1.2] - 2023-07-25

### Added

### Fixed

### Changed

- `keys_from_keystring` and `generate_new_keypair` return a token (hash of pubkey) to be used in signing
- Only publishing sdist on PyPi

### Removed

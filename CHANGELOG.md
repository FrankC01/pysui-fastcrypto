# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - Unpublished

### Added

### Fixed

### Changed

- Bumped py03 from v0.19.0 to v0.20.0
- Bumped maturin from 1.1.0 to 1.3.0

### Removed

## [0.2.0] - 2023-08-27

### Added

- [enhancement](https://github.com/FrankC01/pysui-fastcrypto/issues/3) Sign arbirary message
- [enhancement](https://github.com/FrankC01/pysui-fastcrypto/issues/2) Verify signature

### Fixed

### Changed

### Removed

## [0.1.7] - 2023-08-23

### Added

### Fixed

### Changed

- [change](https://github.com/FrankC01/pysui-fastcrypto/issues/1)

### Removed

## [0.1.4] - 2023-07-30

### Added

- Rust documentation

### Fixed

### Changed

- Updated README.rst

### Removed


## [0.1.3] - 2023-07-28

### Added

- `keys_from_mnemonics` takes phrase and derivation path

### Fixed

### Changed

- `keys_from_keystring` and `generate_new_keypair` now return private key bytess instead of token
- README.rst

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

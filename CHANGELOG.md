# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.5] - 2026-07-17

### Added

### Fixed

### Changed

- Bumped `fastcrypto` (0.1.10 → 0.1.11); transitively resolves serde_with CVE GHSA-7gcf-g7xr-8hxj (3.18.0 → 3.21.0) — denial-of-service panic in KeyValueMap serializer

### Removed

## [0.7.4] - 2026-06-24

### Added

### Fixed

- Upgraded `pyo3` (0.28.3 → 0.29.0) to resolve CVE GHSA-36hh-v3qg-5jq4 (high) and GHSA-chgr-c6px-7xpp (moderate)

### Changed

### Removed

## [0.7.3] - 2026-05-22

### Added

### Fixed

- Refactored GitHub Actions workflow: corrected action versions, restored macOS x86\_64 wheel (cross-compiled), and streamlined release job
- Resolved `GenericArray::as_slice()` deprecation warnings in `derive_key_pair_from_path` (Secp256k1 and Secp256r1 paths)

### Changed

- Updated transitive dependencies (keccak, time, tokio and others) to resolve known CVEs
- Bumped `fastcrypto` (0.1.9 → 0.1.10); transitively resolves rsa CVE-2026-21895 (rsa 0.8.2 → 0.9.10)
- Bumped `maturin` (1.13.1 → 1.13.3) in requirements.txt

### Removed

## [0.7.2] - 2026-04-08

### Added

### Fixed

### Changed

- Update Maturin

### Removed

## [0.7.0] - 2025-05-06

### Added

- github actions builds binary distributions

### Fixed

### Changed

- Bumped `fastcrypto` (0.1.9)

### Removed

## [0.6.0] - 2024-02-08

### Added

- [enchancement](https://github.com/FrankC01/pysui-fastcrypto/issues/10) Add verification of signature using public key

### Fixed

### Changed

- Bumped `maturin` (1.8.2), `twine` (6.1.0) versions in requirements.txt

### Removed

## [0.5.1] - 2024-12-26

### Added

### Fixed

- [bug](https://github.com/FrankC01/pysui-fastcrypto/issues/9) Version 1.8 maturin requires a version in pyproject.toml

### Changed

- Bumped `maturin`, `twine` and `pkginfo` versions in requirements.txt

### Removed

## [0.5.0] - 2024-04-05

### Added

- [enhancement](https://github.com/FrankC01/pysui-fastcrypto/issues/5) - bech32 support

### Fixed

### Changed

### Removed

## [0.4.0] - 2023-12-10

### Added

- [enhancement](https://github.com/FrankC01/pysui-fastcrypto/issues/4)

### Fixed

### Changed

### Removed

## [0.3.0] - 2023-10-25

### Added

### Fixed

### Changed

- Bumped fastcrypto from 1.6 to 1.7
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

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
 
## [1.6.0] - 2026-03-22
 
### Added
- **VEX v1.6.0 Protocol Alignment**: 100% parity with the Rust protocol lockdown.
- **Intent v3 Structure**: Added `schema`, `aid`, and `commands` to the Intent pillar.
- **Authority v3 Structure**: Added `binding_status` and `continuation_token` for high-assurance enforcement.
- **HPKE Intent Privacy**: RFC 9180 encryption (X25519-HKDF-AESGCM) for tool parameters.
- **Local Verification**: Offline Ed25519 signature validation of Gate-issued tokens.
 
### Fixed
- **HPKE Serialization**: Resolved `hpke-js` type-format mismatches for stable cross-stack encryption.
- **Pydantic Hardening (Python)**: Resolved field shadowing warnings in v2 models.
- **Merkle Consistency**: Unified domain separation (0x00/0x01) for the 4-leaf Pillar Tree.
- **Titan-Grade Hardening**: Resolved 18+ TypeScript linting errors/warnings and patched high-severity dependencies via `npm audit fix`.
 

## [1.5.0] - 2026-03-17

### Added
- **Silicon Identity (Attest) Integration**: Native support for hardware-rooted trust (TPM 2.0, Secure Enclaves).
- **VEX Ledger Link**: Added `prev_hash` to Evidence Capsules for stateful chaining.
- **MCS Signals**: Added `supervision` field for multi-model cognitive signals.
- **Automated CI/CD**: GitHub Actions for pytest (Python) and Jest (TypeScript) verification.
- **Trusted Publishers**: Automated PyPI release via OIDC.
- **Branding**: Unified monorepo structure under the `@provnai` (NPM) and `provn-vex-sdk` (PyPI) namespace.

### Fixed
- **Binary Parity**: Achieved 100% bit-for-bit parity between Python and TypeScript implementations.
- **AEM Handshake**: Fixed stateful polling in `ESCALATE` state with exponential backoff.
- **Security**: Added hex validation for `VEX_IDENTITY_KEY` in decorators.
- **TypeScript Safety**: Tightened interfaces and explicitly exported types.

### Changed
- **License**: Switched to **Apache License 2.0**.
- **Python Namespace**: Renamed internal module to `provn_vex_sdk` for consistency.
- **Branding**: Updated all READMEs and documentation for "Titan-grade" professional identity.

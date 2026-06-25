# Changelog

All notable changes to this project will be documented in this file.

This component is part of [ThorsAnvil](https://github.com/Loki-Astari/ThorsAnvil). See the [parent changelog](https://github.com/Loki-Astari/ThorsAnvil/blob/master/CHANGELOG.md) for full release history.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [11.0.0] - 2026-06-24

### Fixed
- Fixed SSL integration tests to use local certs instead of Let's Encrypt

## [9.2.0] - 2026-04-10

### Added
- SSL client certificate validation (`AddClientValidationCheck`)
- SSL server certificate verification enabled by default
- Default values for client SSL connections
- Improved `CertificateAuthority` constructors
- Added `ClientCAListInfo` constructor
- Alternative `getaddrinfo()`-based socket setup
- Mechanism for tracking connection actions
- Load Windows root certificates for SSL

### Fixed
- Fixed buffer resize issue
- Fixed coverage for Homebrew
- Fixed Windows build and certificate handling
- Fixed Linux build
- Improved message handling and exception safety
- Standardized certificate macros

## [9.0.01] - 2026-01-15

### Fixed
- Fixed resize bug
- Improved mocking of standard functions and coverage
- Socket connectivity check before use
- Error now generates exception instead of silent failure

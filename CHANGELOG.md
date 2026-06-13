# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]


## [v0.2.3] - 2026-06-13

[v0.2.3]: https://github.com/thomas-vilte/dave-go/compare/v0.2.2...v0.2.3

In this release, we focused on optimizing the core messaging performance and improving the reliability of MLS operations. We introduced zero-allocation encryption and more descriptive error handling to provide a faster and more stable experience.

### 🚀 Performance

- Implemented zero-allocation encryption and ratchet caching to significantly reduce memory overhead and improve processing speed.

### 🛡️ Stability & Reliability

- Extended the MLS epoch activation timeout to ensure more reliable synchronization and prevent premature failures.

### 🔧 Developer Experience

- Introduced detailed MLS operation errors to provide clearer feedback and easier debugging.
- Standardized error handling across the project and updated dependencies to the latest versions for a more robust foundation.

## [v0.2.2] - 2026-06-01

[v0.2.2]: https://github.com/thomas-vilte/dave-go/compare/v0.2.1...v0.2.2

We focused on enhancing the stability of secure messaging sessions by implementing robust recovery mechanisms. These changes ensure that MLS states are correctly managed during reconnections and that encryption processes no longer block system performance.

### 🛡️ Security & Session Stability

- We implemented MLS commit recovery to ensure secure communication remains consistent even after unexpected errors.
- We added robust state resets when reconnecting to prevent stale session data from causing synchronization issues.

### 🚀 Performance Improvements

- We optimized the encryption process to be non-blocking, significantly improving overall application responsiveness during secure data handling.

### References

- [#7](https://github.com/thomas-vilte/dave-go/pull/7)

## [v0.2.1] - 2026-05-18

[v0.2.1]: https://github.com/thomas-vilte/dave-go/compare/v0.2.0...v0.2.1

In this patch release, we focused on improving the reliability of our concurrent processes. We addressed a critical synchronization issue to ensure smoother execution of epoch-related tasks.

### 🛡️ Stability & Performance

- Fixed a synchronization issue where the epochReady channel could block goroutines, ensuring more reliable background processing.

## [v0.2.0] - 2026-04-22

[v0.2.0]: https://github.com/thomas-vilte/dave-go/compare/v0.1.0...v0.2.0

In this update, we focused on enhancing the efficiency of our core encryption engine. We introduced significant performance optimizations to frame processing to ensure faster data handling and reduced system overhead.

### 🚀 Performance

- We optimized frame encryption by implementing cipher caching and a dedicated fast path to significantly improve processing speed.

## [v0.1.0] - 2026-04-15

[v0.1.0]: https://github.com/thomas-vilte/dave-go/compare/v0.0.0...v0.1.0

In this release, we focused on improving the project's accessibility and streamlining its core. We localized our codebase documentation and optimized our dependency tree for a more efficient development experience.

### 🔧 Developer Experience

- We translated all internal code comments to English to make the project more accessible to the global developer community.

### 🚀 Performance & Stability

- We pruned unnecessary dependencies to reduce the application's footprint and improve overall maintainability.


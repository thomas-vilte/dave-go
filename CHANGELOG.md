# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]


## [v0.3.2] - 2026-06-29

[v0.3.2]: https://github.com/thomas-vilte/dave-go/compare/v0.3.1...v0.3.2

In this release, we focused on enhancing the reliability of encrypted communications. We refined how the system signals session readiness to ensure smoother and more consistent end-to-end encrypted connections.

### 🔒 Security & Encryption

- We improved the signaling process for End-to-End Encryption (E2EE) session readiness to ensure more reliable and stable secure connections.

## [v0.3.1] - 2026-06-27

[v0.3.1]: https://github.com/thomas-vilte/dave-go/compare/v0.3.0...v0.3.1

In this patch release, we focused on enhancing the reliability of our communication layers. We implemented a robust retry mechanism for MLS callbacks to ensure that transient failures do not disrupt your workflow.

### 🛡️ Stability & Reliability

- Introduced a retry mechanism for MLS callbacks to improve system resilience and ensure reliable data processing during transient network issues.

## [v0.3.0] - 2026-06-27

[v0.3.0]: https://github.com/thomas-vilte/dave-go/compare/v0.2.4...v0.3.0

In this release, we focused on strengthening security and improving the reliability of our messaging infrastructure. We've added new encryption capabilities and implemented more resilient callback handling for the Messaging Layer Security (MLS) protocol.

### 🔒 Security & Encryption

- We implemented passthrough encryption to provide more robust data protection and privacy.
- We added a sole member reset feature to improve management flexibility for individual group members.

### 🛡️ Stability & Reliability

- We introduced a retry mechanism for MLS callbacks to ensure more reliable and consistent communication handling.

## [v0.2.4] - 2026-06-15

[v0.2.4]: https://github.com/thomas-vilte/dave-go/compare/v0.2.3...v0.2.4

In this patch release, we focused on improving the visibility into system health and performance. We've enhanced our logging context and added better tracking for system degradation to help identify and resolve issues more efficiently.

### 🛡️ Stability & Observability

- We enhanced our logging context to provide more detailed insights, making it easier to troubleshoot issues.
- We improved how we track system degradation to ensure better visibility into performance health.

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


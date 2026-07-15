# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]


## [v0.5.1] - 2026-07-15

[v0.5.1]: https://github.com/thomas-vilte/dave-go/compare/v0.5.0...v0.5.1

In this release, we focused on improving system transparency by adding new tracking metrics. We introduced detailed statistics for decryption activities and proposal rejections to provide better insights into your workflows.

### 📊 Analytics & Monitoring

- We added comprehensive statistics for decryption tasks and proposal rejections to help monitor system health and decision logic.

## [v0.5.0] - 2026-07-14

[v0.5.0]: https://github.com/thomas-vilte/dave-go/compare/v0.4.0...v0.5.0

In this release, we focused on expanding channel interaction capabilities and modernizing our internal API structure. We've introduced more robust channel handling and upgraded our core messaging dependencies to provide a more stable foundation.

### 📡 Channel Management

- We added support for handling channel movements and follow modes, enabling more dynamic interactions within the platform.

### 🔧 Developer Experience & Stability

- We introduced functional options to provide a more flexible and idiomatic way to configure the library.
- We upgraded the core mls-go dependency to v1.6.0 to ensure better performance and compatibility with the latest messaging standards.

## [v0.4.0] - 2026-07-07

[v0.4.0]: https://github.com/thomas-vilte/dave-go/compare/v0.3.2...v0.4.0

In this release, we have significantly strengthened the security and reliability of our end-to-end encryption implementation. We introduced rigorous MLS validation, improved media key handling, and more resilient session management to ensure a secure and stable communication environment.

### 🔒 Security & Protocol Validation

- Implemented strict validation for MLS commit proposals and group identities to ensure secure group membership.
- Added secure media key ratcheting and nonce expansion to protect media streams from unauthorized access.
- Introduced a passthrough guard for E2EE to prevent unencrypted data leaks during session transitions.
- Enhanced validation for proposal senders, types, and external joiners to prevent unauthorized session changes.
- Added support for processing DAVE revoke proposals and handling protocol v0 downgrades for better compatibility.

### 🚀 Session Reliability & Performance

- Improved session robustness with comprehensive recovery and retention testing to ensure stable connections.
- Implemented exponential backoff and interruptible retries for more resilient network operations under poor conditions.
- Added a WaitReady method to allow applications to synchronize with E2EE session readiness.
- Introduced a Closer interface to ensure graceful teardown of resources and prevent memory leaks.
- Enhanced tracking of recovery and transition statistics for better observability and debugging.

### 🛠️ Media & Protocol Enhancements

- Refined media handling and epoch transitions for smoother stream continuity during key rotations.
- Exposed the MLS epoch authenticator to support out-of-band verification of session security.
- Provided access to the protocol version to help applications determine E2EE feature availability.

### 🐛 Bug Fixes

- Resolved an issue where the E2EE indicator would flicker during epoch transitions.
- Fixed a bug that caused the recovery watchdog to re-arm unnecessarily during transport failures.

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


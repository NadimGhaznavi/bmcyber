# Changelog

## [Unreleased]

### Summary

Establish BMCyber's engineering foundation with pinned BMForge skills and application release scaffolding. Align the proposed MyCount integration with service-selected ban durations and kernel-owned expiry, so Fail2ban ticket expiry cannot shorten a block.

### Added

- Install the project, constants, localization, and installation skills with a local manager and revision lock.
- Add project instructions, BMCyber application metadata, and release tooling with deployment-disabled lifecycle stubs.
- Document application log registration, the proposed `fail2safe` event format, trusted client IP handling, and validation requirements for timed bans in `pages/application-log-integration.md`.
- Pin BMForge ZMQ 0.4.0, Fail2ban 0.1.0, and nftables 0.1.0 skills at cached source revision `0002bd59ee8e` for the agreed host-local blocking implementation.

### Changed

- Update the pinned Fail2ban and nftables contracts to `0.2.0` from BMForge `0.19.1` (`609326cb618e`): use ban-only actions and kernel-owned expiry without application ban tracking or saved deadlines.
- Point offline BMForge checks at the dedicated clean main cache; retain the other five pinned skills and the unchanged manager.
- Refresh the application integration guide with root/group IPC permissions, the native Fail2ban ticket interval, JSON policy configuration, and stateless restart/reboot behavior.

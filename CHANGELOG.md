# Changelog

## [Unreleased]

### Summary

Refresh the pinned BMForge installation guidance and starter installer template with support for an application-owned production Python environment.

### Changed

- Update `bmforge-installation` from `0.1.1` to `0.1.2` and refresh the installer template bundled with `bmforge-project` at cached BMForge revision `f2fe90fd395e`; record both bundle fingerprints and revisions in the lock file.
- Include production virtual-environment ownership, dependency installation and deployed-path guidance in the pinned bundles. BMCyber's application installer and runtime are unchanged.

## [0.3.0] - 2026-10-31 @ 08:58

This release is named for the element **Seaborgium  (Sg)**. Seaborgium was named after Glenn Seaborg while he was still alive, an unusual honor for an element discoverer.

### Summary

Make BMCyber's GitHub Pages documentation available in Ukrainian using R3el's existing locale and shared language selector.

### Added

- Translate the homepage, installation and operation guide, and application security-log integration guide using `lang: uk`, `locale: uk` and paired translation keys.
- Add `/uk/` and `/uk/pages/.../` URLs with localized navigation, baseurl-aware links and stable section anchors; retain the English-only changelog and unchanged executable examples.

## [0.2.0] - 2026-10-31 @ 08:30

### Summary

Refresh the pinned BMForge engineering guidance and prepare BMCyber documentation for GitHub Pages using BMForge's canonical scaffold, with BMDynIP as the project reference.

### Added

- Install the pinned BMForge GitHub Pages skill `0.1.0` at cached revision `1f98e6dc89ba`.
- Add the shared dark theme configuration and main-only GitHub Pages workflow for `bmcyber.osoyalce.com`, reusing BMDynIP's author settings and BMCyber's existing logo.

### Changed

- Update all seven installed skill bundles and their integrity locks to cached BMForge revision `1f98e6dc89ba`; component specification versions remain unchanged.
- Refresh the shared component catalogue and manager with support for the optional GitHub Pages skill; application dependencies remain unchanged.
- Move the detailed README overview to the documentation homepage, retain a short website-linked README, and add English metadata and baseurl-aware navigation to both existing guides.
- Ignore generated Jekyll output and exclude application source, configuration and tooling from the documentation site.

## [0.1.0] - 2026-10-31 @ 06:54

This release is named for the element **Nobelium (No)**. Nobelium was named for Alfred Nobel, the inventor whose fortune established the Nobel Prizes.

### Summary

Implement host-local timed IP blocking through a root IPC service, a Fail2ban action client and nftables. BMCyber selects the default 20–24-hour duration while the kernel owns expiry; group permissions restrict local callers and the application keeps no ban state.

### Added

- Install the project, constants, localization, and installation skills with a local manager and revision lock.
- Add project instructions, BMCyber application metadata, and release tooling with deployment-disabled lifecycle stubs.
- Document application log registration, the proposed `fail2safe` event format, trusted client IP handling, and validation requirements for timed bans in `pages/application-log-integration.md`.
- Pin BMForge ZMQ 0.4.0, Fail2ban 0.1.0, and nftables 0.1.0 skills at cached source revision `0002bd59ee8e` for the agreed host-local blocking implementation.
- Add the root IPC service, ban/health protocol, validated policy configuration, English CLI catalogue, and nftables adapter with owned-table verification and no persistent ban tracking.
- Add native Fail2ban filter, ban-only action and disabled MyCount jail, plus sequential service controls and complete install/upgrade/uninstall ownership and health verification.
- Add unit and lifecycle tests, isolated native firewall/Fail2ban/root-service/permission checks, and installation and operation documentation.

### Changed

- Update the pinned Fail2ban and nftables contracts to `0.2.0` from BMForge `0.19.1` (`609326cb618e`): use ban-only actions and kernel-owned expiry without application ban tracking or saved deadlines.
- Point offline BMForge checks at the dedicated clean main cache; retain the other five pinned skills and the unchanged manager.
- Refresh the application integration guide with root/group IPC permissions, the native Fail2ban ticket interval, JSON policy configuration, and stateless restart/reboot behavior.

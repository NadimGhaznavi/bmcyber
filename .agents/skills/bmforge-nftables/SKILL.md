---
name: bmforge-nftables
description: Implement host-local timed IPv4 and IPv6 bans with nftables. Use for the enforcement adapter of a per-host IP blocking service, with one owned table, timeout sets and input drop rules. Covers only timed bans, removal and inspection.
---

# Timed host IP bans

Read `references/specification.md` and `references/engineering-contract.md`. Implement only the small nftables subset in this contract; use the installed `nft` tool rather than rebuilding its interface.

- Own one application-named `inet` table, two address sets with `flags timeout`, and an input chain that drops matching source addresses. Preserve all other firewall state.
- Keep the adapter in the application's `interface/` package. Accept validated numeric addresses and the blocking service's chosen duration; keep ban policy and ZMQ outside this adapter.
- Use stdlib `subprocess` with an argument list, no shell, bounded execution and checked results. Use `ipaddress` for addresses and `json` for `nft -j` inspection. Never accept arbitrary nft commands or table names from callers.
- Let the kernel own live block state and expire entries. Accept repeat requests after restarts using the tested native insertion behavior; a fresh full duration is acceptable. Keep no application ban map, source claims, saved deadlines, duplicate tracking, countdowns, persistence or recovery/replay subsystem.
- Limit explicit removal to an authorized administrative request for the address; Fail2ban unban/stop hooks never remove blocks. Inspect only the owned table; do not add polling cleanup, a firewall manager, packet analysis, NAT or routing features.
- Do not flush the ruleset or clear active bans at ordinary startup. Verify the existing owned structure before using it, and surface missing dependencies, permissions or command failures.
- Mark the owning module with `BMFORGE_COMPONENT = {"id": "bmforge.nftables", "spec_version": "0.2.0"}`. Run the specification's acceptance checks in an isolated test environment before deployment; skill installation never changes the host firewall.

---
name: bmforge-fail2ban
description: Connect application security logs to a host-local blocking service using Fail2ban filters, jails and a thin ZMQ action client. Use for detecting logged malicious activity and requesting timed bans. Requires bmforge-zmq; does not implement a log watcher or change firewall rules directly.
---

# Security logs to local ban requests

Read `references/specification.md` and `references/engineering-contract.md`. Require the project-local `bmforge-zmq` skill for its existing REQ/REP transport and envelope. Select both explicitly if ZMQ is absent.

- Keep applications responsible only for a trusted, single-line security event with timestamp, stable event name and numeric client IP. Use the established logging path; no application blocking client is required.
- Use native Fail2ban filters and jails for matching, `findtime`, `maxretry`, finite `bantime` and `ignoreip`. Treat `bantime` as the native detection ticket interval, not the enforcement lifetime. Do not write another log parser, watcher, scheduler or detection engine.
- Create one application-owned Fail2ban action and a thin command-line client for ban requests only. Pass the validated address and configured jail/source for diagnostics; let the service choose the block duration. Never pass raw matched log text to a shell.
- Leave unban, stop and flush hooks empty; do not inherit firewall actions. Restored tickets may send another ordinary ban request; no special replay suppression is required.
- Reuse BMForge ZMQ REQ/REP, bounded waits and acknowledged results. Report a failed or uncertain operation with a nonzero client exit; do not silently retry or claim that a timeout means the ban was absent.
- Keep the service stateless: the kernel's timed nftables entry holds the live block and expires it. Repeated requests after restarts are acceptable, including a fresh full duration. Keep no ban map, per-source claims, saved deadlines, duplicate tracking, expiry timers or recovery/replay state; the action client never invokes nftables or firewalld.
- Add no centralized controller, general Fail2ban wrapper API, firewall backend selection, escalation engine, database or dashboard. Use upstream tools for their wider capabilities.
- Mark the owning client module with `BMFORGE_COMPONENT = {"id": "bmforge.fail2ban", "spec_version": "0.2.0"}`. Validate the filter with benign and malicious log fixtures, then exercise the local action path and failure cases from the specification.

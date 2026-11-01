---
title: Fail2ban Security Log Detection
lang: en
locale: en-US
language_name: English
component_id: "bmforge.fail2ban"
spec_version: "0.3.0"
spec_status: "draft"
translation_key: bmforge-component-fail2ban
---

**Component ID:** `{{ page.component_id }}` · **Specification:** `{{ page.spec_version }}` ({{ page.spec_status }})

## Intent and prerequisite

Consume an application's **systemd journal** security events on the same host. The independently selected [Security Event Producer]({{ site.baseurl }}{% link pages/component-security-events.md %}) emits one trusted record; **native Fail2ban** reads it from journald, optionally counts matches per address, and invokes a thin action client over [BMForge ZMQ REQ/REP]({{ site.baseurl }}{% link pages/component-zmq.md %}). The local service enforces bans through [nftables]({{ site.baseurl }}{% link pages/component-nftables.md %}). Each host operates independently. Follow the [engineering contract]({{ site.baseurl }}{% link pages/engineering-contract.md %}).

**Requires `bmforge-zmq` in the blocking/consumer project** for its action client. Select both skills explicitly or use an already pinned ZMQ skill. The manager rejects a missing prerequisite before writing files. The event-producing application needs only `bmforge-security-events` and **must not** inherit this ZMQ dependency. The enforcement project separately selects `bmforge-nftables`; selecting this skill does not grant permission to modify the host firewall.

This contract covers only native journal-based filter/jail configuration and a ban-request action client; the event's format and trusted address are owned by the independent producer. The blocking service chooses the duration; the kernel holds the active block and expires it. Do not reproduce Fail2ban's log watcher, matching engine, scheduler, CLI or administration API. No centralized controller, escalation rules, new database, dashboard, direct firewall action or general backend abstraction is selected.

## Approved runtime modules

| Origin | Module/tool | Purpose |
| --- | --- | --- |
| Host package | `fail2ban`, `fail2ban-client`, `fail2ban-regex`, `python3-systemd` (or distribution equivalent), `systemd-journald` | Native journal backend, jail configuration and verification |
| Python stdlib | `argparse`, `ipaddress`, `sys` | Thin client's argument parsing, numeric address validation and exit status |
| Existing component | `bmforge-zmq` approved modules, including `zmq` | Existing REQ/REP envelope, bounded exchange and acknowledged result |

Record the tested host package version in the application. Use native configuration files; do not import Fail2ban internals or introduce another Python wrapper library. Changes to this inventory require approval and a revised specification. Application policy and existing application logging remain outside the action client's module inventory.

## Systemd journal event boundary

**Only journald is supported as the event delivery channel for this integration.** The producing application's service sends exactly one UTF-8 security line to its normal stdout/stderr journal stream, via the [Security Event Producer]({{ site.baseurl }}{% link pages/component-security-events.md %}). The producer formats a local `yyyy-mm-dd hh:mm:ss` timestamp, fixed event identifier and trusted numeric IPv4/IPv6 source; business logic only calls `emit("abuse")`. The producing application has no ZMQ client, rate counters, delivery acknowledgements, retries, local ban storage, firewall operations or knowledge of the blocking service.

Example journal `MESSAGE` (the journal has additional trusted metadata):

```text
2026-10-31 17:19:00 SECURITY event=abuse ip=192.0.2.10
```

Do not add a file writer, `logpath`, file rotation, an application log watcher, or a fallback to file-based backends. Confirm the actual running service writes unprefixed messages to its journal unit, with `StandardOutput=journal` and `StandardError=journal` where appropriate. Read the unit's trusted `_SYSTEMD_UNIT` value from `journalctl -u <unit> -o verbose`; do not trust a caller-supplied syslog identifier, forwarded HTTP header or arbitrary JSON field as the source.

Journal rate limits or service failures may drop events. Fire-and-forget means **best-effort publication**, not guaranteed enforcement. Do not add queues, application retries or a second delivery mechanism to solve this hypothetical failure. The host must have native `python3-systemd` bindings installed for the Fail2ban service's interpreter. These are **Fail2ban's host dependencies**, not additional Python requirements in the producing application's venv.

## Native journal filter and jail

Configure `backend = systemd` explicitly for this application's jail. Use `journalmatch = _SYSTEMD_UNIT=<real-app-unit>.service` in the filter's `[Definition]` or jail-specific override, scoped to the verified originating unit, and **do not configure `logpath`**. Keep the owned configuration narrow: one filter per required event format, an app-specific `.local` jail and the existing ban-only action. Leave native vendor files, unrelated jails and other service logging unchanged.

For the canonical producer format, Fail2ban recognizes the local timestamp and matches the remaining fixed line using this filter example:

```ini
[Definition]
failregex = ^\s*SECURITY event=abuse ip=<HOST>\s*$
ignoreregex =
journalmatch = _SYSTEMD_UNIT=myapp.service
```

Use the **actual** deployed unit and intended event name, not the example literals. Require `usedns = no`, appropriate host exemptions through `ignoreip` and the blocking service, and explicit native `findtime`, `maxretry`, `bantime`, plus the configured `action`. The logger must not wrap messages with a second timestamp, `WARNING` prefix, Gunicorn formatter, exception text or attacker-controlled content. Anchored matching and journal unit scoping are both required to prevent spoofed or unrelated entries becoming ban requests. Verify IPv4 and IPv6 matching and timestamp recognition with **native Fail2ban**, not just a Python regex.

Fail2ban owns all **per-source event counting**. Choose the meaning of an event deliberately: if one record already means confirmed abuse, set `maxretry = 1`; if events are countable actions, configure `maxretry > 1` with a suitable `findtime` in the jail. Do not count the same threshold in the application and Fail2ban, or make the application share rate counters across Gunicorn workers. Fail2ban naturally consumes journal entries from all workers under the same unit.

Keep a finite positive `bantime` as Fail2ban's own ticket suppression interval, not the kernel ban duration. Ticket expiration must not remove or shorten the blocking service's kernel entry. Only an app-specific, explicit deployment decision can change `findtime`, `maxretry`, the event semantics, or protected addresses; there is no universal abuse threshold.

### Example jail (disabled until verified)

```ini
[myapp-abuse]
enabled = false
backend = systemd
filter = myapp-security
usedns = no
findtime = 60
maxretry = 1
bantime = 20h
ignoreip = 127.0.0.0/8 ::1
action = local-ban[source=myapp-abuse]
```

The `journalmatch` appears in the filter above. The `action` names an already-implemented consumer-side ZMQ command, not a new action transport. This is illustrative, not a policy for every application. No application-side event duplication or cache is implied.

## Action client boundary

Use native `actionban` to invoke a fixed, absolute application-owned executable. Pass only the validated `<ip>` and a configured jail/source identifier for diagnostics. Do not send Fail2ban's ticket duration, deadline or an unban request. The blocking service chooses the effective duration from its own policy when inserting a new timed kernel entry.

Leave `actionunban`, `actionstop` and `actionflush` empty; do not inherit vendor firewall actions. Ticket expiry, manual jail unban and jail shutdown must leave enforcement untouched. Restored tickets may send another ordinary ban request; no special replay suppression is required.

The client converts these few arguments into the blocking service's declared ban request using the existing BMForge envelope. It has no log parsing, detection, policy or firewall code. Keep action parameters operator-controlled, restrict identifiers to a safe token alphabet and quote arguments; never interpolate `<matches>` or raw log text into a command.

Use the selected same-host ZMQ endpoint: a named filesystem IPC socket or explicitly configured loopback TCP, never a wildcard bind or remote controller. Apply the ZMQ contract's IPC permissions or the application's declared local authorization boundary; loopback reachability alone does not authenticate a caller. Do not invent a new authentication framework in this skill.

Return exit status zero only after a successful service acknowledgement of the requested result. A missing service, rejected request, timeout or error reply produces a visible diagnostic and nonzero exit. A lost reply leaves an uncertain outcome; do not blindly retry or extend a ban. Reuse the ZMQ contract's socket cleanup after a failed REQ exchange.

Keep the blocking service stateless between requests. The timed nftables entry is the sole live enforcement state; a jail/source identifier is diagnostic metadata, not an independent claim. Repeated requests after a restart are acceptable, including a fresh full duration; do not reconstruct old deadlines or track duplicates. Add no application ban map, source-claim ledger, expiry scheduler, persistence or recovery/replay subsystem. Fail2ban retains its own native detection state; the application does not mirror it. If kernel entries are lost, subsequent detection can request a new block.

## Traceability and references

Place `BMFORGE_COMPONENT = {"id": "bmforge.fail2ban", "spec_version": "0.3.0"}` in the action client's owning module, following [specification traceability]({{ site.baseurl }}{% link pages/specification-lifecycle.md %}). Follow the [installation lifecycle]({{ site.baseurl }}{% link pages/component-installation.md %}) for owned filters, jail/action files and executable; installing the skill itself never enables a jail or starts a service. This draft still requires validation in the standalone consuming project.

The official [systemd-journald documentation](https://www.freedesktop.org/software/systemd/man/latest/systemd-journald.html) describes how stdout/stderr records reach the journal. Fail2ban's native [jail.conf manual](https://github.com/fail2ban/fail2ban/blob/master/man/jail.conf.5) describes `backend = systemd`, `python3-systemd` and `journalmatch`. Verify the installed versions on the consuming host.

Consult upstream [jail/filter/action documentation](https://github.com/fail2ban/fail2ban/blob/master/man/jail.conf.5) and [action configuration example](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/dummy.conf) for native details. They do not expand this contract's supported subset.

## Acceptance checks

1. Select `bmforge-fail2ban` plus explicitly selected/already pinned `bmforge-zmq` in the **blocking project**; reject missing ZMQ before writing files. Independently select/install `bmforge-security-events` **alone** in a producer project without ZMQ, Fail2ban or nftables.
2. On a disposable systemd host, confirm the real application service publishes unprefixed canonical `MESSAGE` records to journald, with the correct `_SYSTEMD_UNIT` and validated trusted IPv4/IPv6 addresses. A synthetic logfile fixture alone is insufficient. Confirm `backend = systemd`, available Fail2ban `python3-systemd` bindings and a unit-scoped `journalmatch`; reject `logpath` or a file backend for this component.
3. Verify the real journal with `journalctl -u myapp.service -o cat` and `fail2ban-regex -m '_SYSTEMD_UNIT=myapp.service' systemd-journal /etc/fail2ban/filter.d/myapp-security.conf`, using the real deployed unit/filter. Check timestamp and numeric address recognition, benign lines, wrong event names, attacker-controlled imitations, and both IP families. Confirm the disabled jail configuration passes `fail2ban-client -t` before enabling it.
4. Start with **real application requests**, including through the trusted proxy and across multiple workers where used. Confirm the application emits only the selected semantic event and trusted address, journald records it, and Fail2ban observes its native count/window. Below-threshold events and `ignoreip` sources must not invoke the action; at threshold, exactly the expected action invokes the existing local ZMQ client and the blocking service receives the correct source.
5. Test a missing listener, rejected result, error reply or lost acknowledgement: the consumer action reports nonzero without direct firewall calls or retries. Ticket expiry, manual jail unban and jail stop leave the block untouched; only `actionban` sends enforcement requests.
6. Restart/reload the jail without clearing kernel entries, and accept ordinary later ban requests from new/restored events. Do not introduce source-claim state, replay ledgers or expiration workers. **Do not re-prove nftables' established basic IP-blocking behavior as a condition for adopting this journal integration.** The independent blocking service already owns that test contract.


---

[Timed Host IP Bans]({{ site.baseurl }}{% link pages/component-nftables.md %}) · [Component Blueprints]({{ site.baseurl }}{% link pages/component-blueprints.md %})

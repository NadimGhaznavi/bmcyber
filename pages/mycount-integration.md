---
title: "MyCount journal integration"
lang: en
locale: en-US
language_name: English
translation_key: bmcyber-mycount-integration
---

MyCount publishes security events through `mycount-server.service`'s normal
stderr stream. Native Fail2ban reads that unit's journal, counts per IP and
invokes BMCyber's existing acknowledged ban client. MyCount has no BMCyber
client, delivery acknowledgement, retry queue or shared rate counter.

## Events and policies

| Jail | Event | `findtime` | `maxretry` |
| --- | --- | --- | --- |
| `bmcyber-mycount-flood` | `collection_request` | 60 seconds | 60 |
| `bmcyber-mycount-malformed` | `malformed_payload` | 60 seconds | 5 |

`collection_request` is emitted once per attributable `POST /count`, before
origin validation, body parsing, geolocation or persistence. An allowed-origin
submission additionally emits `malformed_payload` for JSON, content-type,
body-size or visit-schema validation failures. An origin rejection contributes
only to the request count. Health checks, OPTIONS, counter reads, unrelated
routes and analytics bot classifications do not produce either event;
database/geolocation failures do not produce the malformed event.

A malformed submission contributes to both counts. Native Fail2ban combines
events across sites, page URLs and collector workers for the same numeric IP.
The 60th request or fifth malformed submission within the window requests a ban.
This is asynchronous detection: journal/output loss can lose events, and
MyCount does not synchronously reject a request with 429 at these thresholds.

Both jails use `usedns = no`, loopback exemptions and a finite `bantime = 20h`.
Review administrative, monitoring and proxy exemptions before activation.
Keep required protected addresses in BMCyber's `ban.protected_ips` as well.
The ticket interval belongs to Fail2ban; BMCyber independently selects a fresh
20–24-hour kernel timeout for each acknowledged ban request. Two jails may
independently request the same IP; another request may refresh the timeout.
The source identifier is diagnostic metadata. There is no claim ledger or
deduplication state. A ban affects inbound traffic to the entire host.

## Trusted journal boundary

The filter requires the trusted metadata match:

```ini
journalmatch = _SYSTEMD_UNIT=mycount-server.service
```

Confirm that exact originating unit on the installed host. MyCount's other
units, such as `mycount-control.service`, are not event producers. No logfile
or `logpath` is configured. The host Fail2ban interpreter needs its distribution
`python3-systemd` bindings and readable system-journal files; these packages
are not added to either application's venv.

Canonical journal `MESSAGE` values look like:

```text
2026-11-01 10:00:00 SECURITY event=collection_request ip=192.0.2.10
2026-11-01 10:00:00 SECURITY event=malformed_payload ip=2001:db8::10
```

MyCount resolves the address at ingress. Its trusted local Caddy proxy
overwrites `X-MyCount-Client-IP`; the backend accepts that header only from
the configured immediate proxy peer. Preserve the loopback listener and
proxy access boundary. Test actual proxy requests rather than supplying a
forged forwarded header. MyCount rejects invalid or missing trusted source
attribution and never substitutes the proxy's IP.

Fail2ban 1.1.0's systemd backend supplies journal time separately and adds
hostname/process metadata before `MESSAGE`. The owned filter uses native
`common.conf` journal-prefix matching, requires the embedded local timestamp
and anchors the exact event and numeric address. The journal timestamp drives
the native counting window. An expression anchored directly at `SECURITY`
would miss this input. No application logger prefixes, free text, hostnames
as addresses, scoped IPv6 or extra message lines are accepted.

## Installation and lifecycle

The installer owns:

- `/etc/fail2ban/filter.d/bmcyber-mycount.conf`
- `/etc/fail2ban/jail.d/bmcyber-mycount.local`
- `/etc/fail2ban/action.d/bmcyber.conf`

Fresh installations ship both jails with `enabled = false`. Existing jail
configuration is preserved on reinstall/upgrade, including exemptions and
enablement. Uninstall stops only the two named jails, retains their settings
in `/opt/prod/bmcyber/conf/mycount-jails.local`, then removes owned resources.
Reinstallation restores that saved configuration. Unrelated jails and vendor
files are untouched. This does not provide migration from the retired logfile
integration; remove a disposable old installation using its matching release
checkout before installing this implementation.

`scripts/services start` starts BMCyber before starting Fail2ban and loading
the two owned jail configurations. `stop` stops these jails before BMCyber;
`restart` validates application and native Fail2ban configuration before
stopping. Other Fail2ban jails remain running. Disabled/absent owned jails are
normal; a daemon communication failure is reported rather than ignored.

Both jails use the existing fixed action launcher with their own source IDs.
Only `actionban` makes a request. `actionunban`, `actionstop` and `actionflush`
are empty. Ticket expiry, manual unban and jail shutdown leave kernel bans
untouched. A missing listener, rejected request or lost acknowledgement returns
a visible error without retry or direct firewall fallback.

## Acceptance and activation

Activation is an operator action after validation on a disposable systemd host.
Start with requests through the actual installed Caddy and MyCount services.
Inspect both the raw message and trusted metadata:

```sh
journalctl -u mycount-server.service -o cat
journalctl -u mycount-server.service -o verbose
sudo fail2ban-regex -m '_SYSTEMD_UNIT=mycount-server.service' systemd-journal 'bmcyber-mycount[event=collection_request]'
sudo fail2ban-regex -m '_SYSTEMD_UNIT=mycount-server.service' systemd-journal 'bmcyber-mycount[event=malformed_payload]'
sudo fail2ban-client -t
```

Verify these cases using disposable source addresses outside exemptions:

1. Original IPv4/IPv6 attribution through the trusted proxy; forged visitor
   headers cannot select an address. Both signals have exact unprefixed messages.
2. 59 collection requests cause no flood action; the 60th within 60 seconds
   does. Four malformed requests cause no malformed action; the fifth does.
   Repeat across workers and allow a window to expire to verify reset behavior.
3. Benign/unrelated records, other units, malformed addresses and exempt IPs
   cause no action. Review administrative and proxy exclusions explicitly.
4. The resulting BMCyber request contains the expected IP and jail source.
   Missing listeners, rejection and lost replies fail visibly without retry.
5. Ticket expiry, manual jail unban, jail stop and restart leave existing
   kernel bans under BMCyber's established enforcement contract.

On that disposable host, enable one jail at a time by setting its `enabled`
value to `true` in the owned `.local` file, validate configuration, and reload
that named jail. Restore disabled settings when finished. Production deployment
and enablement require their own explicit authorization.

The local native tests cover parsing, realistic formatter input, counters,
exemptions, time windows and the real CLI/IPC action with a fake firewall:

```sh
BMCYBER_FAIL2BAN_ROOT=/path/to/extracted-package python3 -B -m pytest -q tests/test_mycount_native.py
```

Use `/` for a distribution package installed on the test machine. No package
is installed by the tests. Journal metadata is synthetic; these tests do not
prove real Caddy/MyCount/systemd delivery. That complete host acceptance has
not been performed here, so both shipped jails remain disabled.

---

[Documentation index]({{ site.baseurl }}{% link index.md %})

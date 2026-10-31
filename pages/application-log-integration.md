# Registering an application's security log

This guide describes BMCyber's application log integration. MyCount on
wintermute is the first use case. The service, client, filter and action are
implemented; the supplied MyCount jail remains disabled until its deployment
log path and trusted client-IP handling are verified. This guide follows the
pinned BMForge Fail2ban and nftables contracts at specification `0.2.0` from
BMForge `0.19.1`. See [installation and operation](installation.md) for
prerequisites, deployment and the IPC protocol.

## How an event becomes a ban

```text
Internet → TekSavvy → wintermute:80/443 → Caddy → MyCount
                                                   |
                                            security log
                                                   |
                                                Fail2ban
                                                   |
                                            ZMQ action client
                                                   | IPC
                                            BMCyber service
                                                   |
                                            nftables timed ban
```

The application detects abuse and logs the offending client's IP. Fail2ban
monitors the registered log and invokes BMCyber's action client when its jail
threshold is reached. The client requests a ban over a local IPC socket and
reports success only after the service acknowledges enforcement.

The resulting ban drops all inbound traffic from that IP on wintermute,
regardless of port or hostname. This also prevents that source from reaching
other sites through Caddy on wintermute. It is not limited to MyCount's HTTP
endpoint. SnakeWeb's backend on neuromancer is a later integration.

Applications need no ZMQ client, firewall privileges or direct connection to
BMCyber. They only need to emit the security record below.

## Local IPC access

The BMCyber systemd service runs as root. Its runtime directory is
`/run/bmcyber/`, owned by `root:bmcyber` with mode `0750`. The named filesystem
IPC socket is owned by `root:bmcyber` with mode `0660`. Only root can create
or remove entries in the directory; members of the `bmcyber` Linux group can
connect to the socket. Apply restrictive permissions from socket creation,
not after a period of public access.

Any non-root account running the ZMQ client must belong to the `bmcyber`
group. For the MyCount integration, this is the account running Fail2ban's
action client. MyCount itself only needs to write its log. systemd recreates
the transient runtime directory after reboot; clients only connect and never
create the directory or remove socket files.

## What the application must log

Write one UTF-8 line to the application's existing log when its abuse detector
decides that a client should be banned:

```text
2026-10-31 14:30:00 SECURITY event=fail2safe ip=192.0.2.10
```

An IPv6 example is:

```text
2026-10-31 14:30:01 SECURITY event=fail2safe ip=2001:db8::10
```

These are documentation addresses, not real ban targets.

| Field | Required value |
| --- | --- |
| Timestamp | `yyyy-mm-dd hh:mm:ss`, 24-hour clock, no fractional seconds, in the host/application local timezone used by Fail2ban. |
| Marker | Literal `SECURITY`. |
| Event | Literal `event=fail2safe`; a stable programmatic identifier, never translated. |
| Address | `ip=` followed by one validated numeric IPv4 or IPv6 address, without a port, brackets, zone identifier, hostname or CIDR suffix. |

Use this exact field order and one space between fields. End the record with
a newline. Configure the existing logger to render this security record without
additional prefixes or suffixes; ordinary log entries can retain their existing
format. Flush records promptly enough for Fail2ban to observe them.

MyCount owns flood detection: ordinary analytics POSTs, routine access records
and isolated validation errors must not automatically produce this event.
For this integration, a `fail2safe` record means the application has
already determined abuse; one matching record is sufficient to request a ban.
The actual request-rate threshold remains a MyCount requirement.

Build the record from fixed syntax, an application-selected event identifier
and a validated client address. Keep request bodies, URLs, headers, usernames
and other client-controlled text out of this line. Diagnostic details may be
logged separately, with newlines escaped so they cannot forge a security record.

### Getting the real client IP behind Caddy

MyCount must log the original Internet client's address, not the address of
Caddy, wintermute or the modem. It may use a forwarded client address only
when the immediate connection comes from the explicitly trusted Caddy proxy
and Caddy controls that forwarding information. Do not accept a visitor's
arbitrary `X-Forwarded-For` value or an IP supplied in the analytics payload.

Restrict access to the MyCount listener to the intended proxy path. Validate
and normalize the selected numeric address before constructing the event.
The deployed proxy configuration and MyCount's address selection must be
verified together before enabling bans. See Caddy's
[forwarded-header documentation](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy#defaults).

## Register the log with Fail2ban

Registration is a native Fail2ban jail entry, not a second log-watching
configuration inside BMCyber. Each application gets its own named jail and
absolute log path; applications using the same event format share the filter
and action.

The shipped registration entry is installed at
`/etc/fail2ban/jail.d/bmcyber-mycount.local`:

```ini
[bmcyber-mycount]
enabled = false
filter = bmcyber-security
backend = auto
logpath = /var/log/mycount/mycount.log
usedns = no
findtime = 60
maxretry = 1
bantime = 20h
ignoreip = 127.0.0.0/8 ::1
action = bmcyber[source=bmcyber-mycount]
```

`/var/log/mycount/mycount.log` is an example: replace it with MyCount's actual
deployment log path. Fail2ban must be able to traverse the parent directories
and read the current log, including after rotation. The application must
continue writing to the monitored path after rotation. Avoid broad globs that
include archived copies of the same events.

`maxretry = 1` requests a ban for one classified abuse event. `findtime = 60`
sets a 60-second event-counting window; it is not a ban duration. These are
initial integration settings, not universal detection thresholds.

`bantime = 20h` controls Fail2ban's own detection ticket and suppression
interval. It does not specify the lifetime of the nftables entry. BMCyber
chooses the enforcement duration using the policy below.

Review `ignoreip` for the host's administrative and proxy addresses before
activation. The loopback entries above are only a starting example. Exemptions
also need to be respected by the service's declared protection policy.

The `bmcyber` action uses the jail name as its source identifier.
Its installed definition invokes a fixed application-owned ZMQ executable,
using the same IPC endpoint as the BMCyber service. It must never pass matched
log text to a shell or invoke nftables directly. The client passes only the
validated address and configured source identifier; the source is diagnostic
metadata, not an independently tracked claim on the ban.

Only `actionban` sends an enforcement request. Leave `actionunban`,
`actionstop` and `actionflush` empty, without inheriting vendor firewall
actions. Ticket expiry, manual jail unban and jail shutdown leave the kernel
block intact. No Fail2ban duration or deadline is sent to BMCyber.

Keep the jail disabled until its deployment log path, exemptions and complete
action path have been verified on the target environment. Leave unrelated jails and vendor
configuration files unchanged.

Fail2ban's [jail and filter manual](https://github.com/fail2ban/fail2ban/blob/1.1.0/man/jail.conf.5)
defines native registration, event counting and action configuration.

## Matching the event

The shared filter at
`/etc/fail2ban/filter.d/bmcyber-security.conf` is:

```ini
[Definition]
failregex = ^\s*SECURITY event=fail2safe ip=<HOST>\s*$
ignoreregex =
```

Fail2ban recognizes and removes the timestamp before matching this expression.
Its `<HOST>` token matches the address; the jail's `usedns = no` disables DNS
resolution. Confirm both timestamp recognition and matching with the installed
Fail2ban version. The anchors deliberately exclude unrelated messages and
records containing additional free text.

## Ban duration

For a new entry, BMCyber selects **20 hours plus a random additional duration
from 0 to 4 hours**. nftables expires
the entry automatically; blocked traffic does not reach MyCount and therefore
does not produce further application detections. New abuse after expiration
can trigger a new ban.

The base duration defaults to `DPolicy.BASE_HOURS = 20`; the maximum addition
defaults to `DPolicy.RANDOM_EXTRA_HOURS = 4`. Both are explicit settings in
`/opt/prod/bmcyber/conf/bmcyber.json`:

```json
{
  "ban": {
    "base_hours": 20,
    "random_extra_hours": 4
  }
}
```

Constants supply defaults, production JSON supplies operator overrides, and
one shared resolver serves startup and operational tools. The complete shipped
example is `conf/bmcyber.json`. A missing setting inherits its constant default;
invalid settings fail startup. Application log records do not carry or choose ban durations.

The random addition belongs to BMCyber's policy, not Fail2ban's
`bantime.rndtime`. Because Fail2ban's unban hook is empty, expiration of its
20-hour ticket cannot truncate the additional enforcement time. If the service
base is reduced, also reduce the native ticket interval to no longer than the
minimum service duration, so detection can resume when enforcement expires.

### Restarts and reboots

The kernel's timed entry is the sole live enforcement state. BMCyber keeps no
ban map, per-source claims, saved deadlines, expiry timers or persistent ban
store. An ordinary service restart verifies and reuses active kernel entries
without clearing them.

A repeated request, including one from a restored Fail2ban ticket, is an
ordinary ban request. On tested nftables 1.1.3, repeated native insertion
refreshes the entry with a fresh full duration. BMCyber does not reconstruct
an original deadline or track duplicate requests.

A host reboot loses the kernel entries. BMCyber does not restore them.
Subsequent requests can create new blocks; a restored native Fail2ban ticket
is also such a request and may start a fresh duration. This does not require
an application-owned recovery or replay subsystem.

## Verify before enabling the jail

Prepare a separate fixture file containing current local timestamps, matching
IPv4 and IPv6 events, normal access records, other event names, malformed
addresses and attempts to imitate the marker inside free text. On a host with
the filter installed, inspect matching and timestamp recognition:

```sh
fail2ban-regex /absolute/path/to/security-event-fixtures.log /etc/fail2ban/filter.d/bmcyber-security.conf
```

Only the intended security records should match. Do not append synthetic
events to a live monitored log to test filtering.

Before enabling the jail, validate the complete Fail2ban configuration:

```sh
fail2ban-client -t
```

Then verify the complete path in an isolated environment: one event causes an
acknowledged IPC request and a timed IP ban, exempt addresses remain reachable,
and expiry restores traffic. Verify an unavailable service or lost reply
produces a visible action failure, not a false success. Check rotation,
service restart, repeated insertion and the 20–24-hour policy before production
activation. Verify that Fail2ban ticket expiry, manual jail unban and jail
shutdown send no enforcement request and leave active kernel entries intact.
Verify the IPC permissions from both an authorized non-root group member and
an unrelated unprivileged account.

Native filter and end-to-end Fail2ban/IPC/nftables checks have passed in an
isolated environment, including IPv4/IPv6 enforcement and expiry and actual
IPC group permissions. The target installation on wintermute still requires
its log/proxy configuration and systemd-managed lifecycle verification. See
the [verification record](installation.md#verification).

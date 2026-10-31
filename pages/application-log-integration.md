# Registering an application's security log

This guide defines the proposed application integration for BMCyber. MyCount
on wintermute is the first use case. The service, Fail2ban filter and action
described here are not implemented yet; configuration examples are for review,
not deployment.

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
For this proposed integration, a `fail2safe` record means the application has
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

The following is the proposed registration excerpt for
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
proposed integration settings, not universal detection thresholds.

Review `ignoreip` for the host's administrative and proxy addresses before
activation. The loopback entries above are only a starting example. Exemptions
also need to be respected by the service's declared protection policy.

The proposed `bmcyber` action uses the jail name as its source identifier.
Its installed definition will invoke a fixed application-owned ZMQ executable,
using the same IPC endpoint as the BMCyber service. It must never pass matched
log text to a shell or invoke nftables directly. An unban from one source must
not release another source's active ban for the same IP.

Keep the jail disabled until the filter, action client, service and duration
integration are implemented and verified. This excerpt deliberately omits
`bantime`: the final jail/action timing must implement the policy below rather
than silently inherit Fail2ban's default duration. Leave unrelated jails and
vendor configuration files unchanged.

Fail2ban's [jail and filter manual](https://github.com/fail2ban/fail2ban/blob/1.1.0/man/jail.conf.5)
defines native registration, event counting and action configuration.

## Matching the event

The proposed shared filter at
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

Every new ban lasts **20 hours plus a random additional duration from 0 to
4 hours**. Select the additional duration once for that ban. nftables expires
the entry automatically; blocked traffic does not reach MyCount and therefore
does not produce further application detections. New abuse after expiration
can trigger a new ban.

The base duration must have a central constant default of `20` and an explicit
configuration entry. The proposed BMCyber policy configuration is:

```ini
[ban]
base_hours = 20
random_extra_hours = 4
```

This is a proposed schema, not an existing configuration file. Its installation
path and constant names will be settled during implementation. Application log
records do not carry or choose ban durations.

The final Fail2ban action and BMCyber service must agree on the effective
expiry. A nominal 20-hour Fail2ban unban must not truncate the random addition,
and reloading or restoring a ticket must not sample a new duration or restart
the full interval. Do not assume that setting Fail2ban's `bantime.rndtime`
alone implements this policy: its relationship with incremental bans must be
checked against the deployed version. Duration coordination is an implementation
acceptance requirement, not resolved by the registration excerpt above.

## Verify before enabling the jail

Prepare a separate fixture file containing current local timestamps, matching
IPv4 and IPv6 events, normal access records, other event names, malformed
addresses and attempts to imitate the marker inside free text. On a host with
the proposed filter installed, inspect matching and timestamp recognition:

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
restart and the 20–24-hour expiry contract before production activation.

These checks are instructions for the future implementation; they have not
been executed by creating this document.

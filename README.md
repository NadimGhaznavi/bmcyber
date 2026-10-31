# BMCyber

BMCyber adds host-local timed IP blocking to application abuse detection.
MyCount logs a `fail2safe` event; Fail2ban invokes a thin client over a Linux
IPC socket; the root BMCyber service blocks the address with nftables.

The default block lasts **20 hours plus a random 0–4 hours** and covers all
inbound traffic from the address. Fail2ban's unban, stop and flush hooks are
empty. The kernel holds the ban and expires it; BMCyber keeps no ban database
or expiry worker. Service restarts preserve kernel entries; reboots lose them.
Native Fail2ban ticket restoration may submit a fresh ban request.

The service runs as root. Non-root clients connect through membership in the
`bmcyber` group. The socket is `root:bmcyber`, mode `0660`, under the
`root:bmcyber` runtime directory with mode `0750`. There is no TCP listener.

- [Application log integration](pages/application-log-integration.md): register a log, emit a trusted event and configure Fail2ban.
- [Installation and operation](pages/installation.md): dependencies, configuration, lifecycle commands, protocol and verification.

The supplied MyCount jail is disabled. Set its actual log path and verify
MyCount's client-IP handling behind Caddy before enabling it on wintermute.
Host firewall blocking protects application processing; upstream link
saturation still requires upstream mitigation.

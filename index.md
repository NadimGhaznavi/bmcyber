---
title: "BMCyber"
layout: single
classes: wide
author_profile: true
lang: en
locale: en-US
language_name: English
translation_key: bmcyber-home
permalink: /
---

![{{ site.title }} logo]({{ site.logo | relative_url }})

BMCyber adds host-local timed IP blocking to application abuse detection.
The thin client sends ban requests over a Linux IPC socket; the root BMCyber
service blocks the address with nftables. Two initially disabled Fail2ban jails
consume MyCount's systemd journal for request floods and malformed submissions.

The default block lasts **20 hours plus a random 0–4 hours** and covers all
inbound traffic from the address. Fail2ban's unban, stop and flush hooks are
empty. The kernel holds the ban and expires it; BMCyber keeps no ban database
or expiry worker. Service restarts preserve kernel entries; reboots lose them.
Native Fail2ban ticket restoration may submit a fresh ban request.

The service runs as root. Non-root clients connect through membership in the
`bmcyber` group. The socket is `root:bmcyber`, mode `0660`, under the
`root:bmcyber` runtime directory with mode `0750`. There is no TCP listener.

## Documentation

- [MyCount integration]({{ site.baseurl }}{% link pages/mycount-integration.md %}): journal events, thresholds, exemptions and activation checks.
- [Installation and operation]({{ site.baseurl }}{% link pages/installation.md %}): dependencies, configuration, lifecycle commands, protocol and verification.

Host firewall blocking protects application processing; upstream link
saturation still requires upstream mitigation.

---
title: Timed Host IP Bans
lang: en
locale: en-US
language_name: English
component_id: "bmforge.nftables"
spec_version: "0.2.0"
spec_status: "draft"
translation_key: bmforge-component-nftables
---

**Component ID:** `{{ page.component_id }}` · **Specification:** `{{ page.spec_version }}` ({{ page.spec_status }})

## Intent and scope

Enforce timed source-IP bans on **one host**, using native nftables. Each internet-facing host runs its own independent stack. The application-owned blocking service decides whether and for how long to ban an address; this component applies that decision. The kernel entry holds the live block state and expires it; the service keeps no copy. Follow the [engineering contract]({{ site.baseurl }}{% link pages/engineering-contract.md %}) and [class responsibilities]({{ site.baseurl }}{% link pages/classification.md %}).

The supported subset is one owned table, IPv4/IPv6 timeout sets, input drop rules, address insertion/removal and inspection. Do not build a general firewall API or reproduce nftables. No firewalld dependency, NAT, forwarding, routing, packet detection or centralized ban distribution is selected. [Fail2ban]({{ site.baseurl }}{% link pages/component-fail2ban.md %}) and [ZMQ]({{ site.baseurl }}{% link pages/component-zmq.md %}) are separate capabilities, selected where required.

## Approved runtime modules

| Origin | Module/tool | Purpose |
| --- | --- | --- |
| Host package | `nftables` / `nft`, Linux `nf_tables` | Native rules, timed sets and enforcement |
| Python stdlib | `subprocess` | Checked, bounded `nft` execution without a shell |
| Python stdlib | `ipaddress` | Validate and normalize individual numeric IPv4/IPv6 addresses |
| Python stdlib | `json` | Read the owned table/sets through `nft -j` |

Record the tested host package/kernel versions in the consuming project; require timeout-set support in preflight. Do not install a Python nftables binding or alternative firewall library. Changes to this inventory require owner approval and a revised specification. Application policy and separately selected transports are outside this adapter's module list.

## Owned rules and operations

Keep the table name in trusted application configuration/constants. This illustrative initial structure uses `app_bans`; substitute the application-owned name:

```nft
table inet app_bans {
    set banned_v4 { type ipv4_addr; flags timeout; }
    set banned_v6 { type ipv6_addr; flags timeout; }
    chain input {
        type filter hook input priority -10; policy accept;
        ip saddr @banned_v4 drop
        ip6 saddr @banned_v6 drop
    }
}
```

The chain drops matching sources; its accept policy leaves other traffic subject to the host's other firewall chains. Scope is traffic delivered to this host's input hook. Do not silently extend it to forwarded/container traffic. Verify that the chosen hook sees the real client address: an upstream proxy can make origin-host IP bans ineffective.

| Operation | Required behavior |
| --- | --- |
| Initialize | Create the owned structure if absent; otherwise verify and reuse it. Do not duplicate rules or flush live bans at normal startup. |
| Apply ban | Submit the numeric address to its family set with an explicit positive timeout in seconds chosen by service policy. Repeated requests are acceptable; use the tested native insertion behavior without stored deadlines or duplicate tracking. Keeping an existing countdown or applying a fresh full duration is acceptable. |
| Remove ban | Only an explicit, authorized administrative removal deletes the requested element. Fail2ban ticket expiry, unban or stop must never invoke this operation. An already expired/absent element is an idempotent success after verification; unrelated command errors remain failures. |
| Inspect | List the owned table/sets in JSON and observe remaining expiration. Do not invent a separate query daemon or background polling loop. |

Use an argument vector with `shell=False` and checked return codes. A generated `nft -f -` batch may contain only fixed syntax, trusted identifiers, normalized addresses and validated finite positive integer durations. Reject CIDRs, hostnames, IPv6 zone identifiers, malformed addresses and raw nft input. Verify and document repeated-insertion behavior on the installed version; do not assume `add element` refreshes an existing timeout or hide command errors.

Never run `flush ruleset`, change another table, or persist a snapshot of the entire host firewall. Installation/upgrade/uninstall own only this application's rules and files and follow the [installation lifecycle]({{ site.baseurl }}{% link pages/component-installation.md %}). Restrict firewall modification privileges to the enforcing service. Skill installation does not install packages, start services or edit firewall state.

The kernel is the sole owner of live block state and handles expiration. Keep no application ban map, per-source claims, countdowns, database or saved ban snapshot; add no cleanup loop or recovery/replay subsystem. A service restart verifies and reuses still-active kernel entries. Repeated requests after a restart are ordinary ban requests; no original deadline needs reconstruction. Host reboot or external removal of the owned table loses runtime entries; document that subsequent detection can request a new block.

## Traceability and references

Place `BMFORGE_COMPONENT = {"id": "bmforge.nftables", "spec_version": "0.2.0"}` in the application's owning `interface/` module, following [specification traceability]({{ site.baseurl }}{% link pages/specification-lifecycle.md %}). This draft is a contract for a consuming implementation, not a proven reference adapter.

Use the upstream [nft manual](https://netfilter.org/projects/nftables/manpage.html), especially tables, chains, sets and elements, and [element timeouts](https://wiki.nftables.org/wiki-nftables/index.php/Element_timeouts) for details beyond this subset.

## Acceptance checks

1. In an isolated network namespace or disposable host, initialize twice; observe one owned structure and preserve unrelated sentinel rules and an active ban.
2. Ban test IPv4 and IPv6 sources, observe their input packets dropped and an unbanned source following existing host policy. Observe expiration and restored traffic without a cleanup worker.
3. Repeat requests for an active address, including after a restart; verify the documented native insertion behavior without saved deadlines or duplicate tracking. After expiry, a fresh request creates a new timed entry. Explicitly remove an entry twice, including after natural expiration, without hiding other command failures.
4. Reject malformed addresses, CIDRs, hostnames, IPv6 zone identifiers, shell metacharacters, zero/negative/infinite durations and excessive durations under the project's declared limit before invoking `nft`.
5. Check missing executable, insufficient privileges, invalid existing table structure and command timeout/failure. The service must report failure or uncertainty rather than acknowledge an unapplied ban.
6. Restart the service without clearing active entries and without application ban state. Verify that another ordinary ban request works after the restart. Document that reboot/external-table-removal loses runtime blocks without recovery; subsequent requests create new blocks. Uninstall removes only owned resources.

---

[Fail2ban]({{ site.baseurl }}{% link pages/component-fail2ban.md %}) · [Component Blueprints]({{ site.baseurl }}{% link pages/component-blueprints.md %})

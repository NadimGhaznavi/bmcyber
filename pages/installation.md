---
title: "Installation and operation"
lang: en
locale: en-US
language_name: English
translation_key: bmcyber-installation
---

BMCyber is a single-host root systemd service plus a local Fail2ban action
client. Two initially disabled MyCount jails use native systemd journal
detection. See [MyCount integration]({{ site.baseurl }}{% link pages/mycount-integration.md %})
for their policies and activation checks.

## Prerequisites

Use Linux with systemd, nftables timeout sets, Fail2ban, and Python 3.11 or
newer, including the standard `venv` and `ensurepip` modules (on Debian,
install the system `python3-venv` package). The installer checks host tools but
does not install OS packages. It uses `/usr/sbin/nft` explicitly;
`groupadd`, `systemctl`, `fail2ban-client` and `fail2ban-server` must also be available.

The supported Fail2ban deployment uses the distribution's `/usr/bin/python3`
interpreter. Install its native `python3-systemd` bindings (or distribution
equivalent) in the host environment. BMCyber checks the server script's
interpreter and opens the system journal with that host Python before changing
files or stopping services. At least one readable runtime or persistent system
journal file must exist. These bindings belong to Fail2ban, not BMCyber's venv.
This checks journal readiness; application event matching is a separate integration.

**Global PyZMQ is not required.** `requirements.txt` pins the tested PyZMQ
version; installation and upgrade install it into
`/opt/prod/bmcyber/.venv` with that environment's Python and pip. Package
downloads require a configured package index or an available local wheel cache.
Run the lifecycle commands from a separate source checkout; the running
application never reads `/opt/dev`.

Verified here: Python 3.13.5, PyZMQ 26.4.0/libzmq 4.3.5, nftables 1.1.3,
Fail2ban 1.1.0, and Linux 6.12.111+deb13-amd64. Validate the native behavior
on wintermute's installed versions before deployment.

## Install, upgrade and uninstall

These are operator commands; development and tests do not execute a host
installation automatically.

```sh
sudo scripts/install.sh --check
sudo scripts/install.sh
sudo scripts/upgrade.sh --check
sudo scripts/upgrade.sh
sudo scripts/uninstall.sh --check
sudo scripts/uninstall.sh
```

All three scripts support `--help`. `--check` validates without changing
files, accounts, services, virtual environments or rules; it verifies host
Python `venv`/`ensurepip` support, dependency declarations, existing venv integrity
and Fail2ban journal access without running pip. nftables preflight
still needs firewall inspection/check privileges. Invalid configuration or
missing prerequisites fail before stopping services. Package-index
availability, `pip check` and deployed runtime imports are verified during the
actual install, before the service is started. Editable dependencies and paths
under `/opt/dev` are rejected. An incomplete owned venv or one that enables
global site-packages is rejected rather than silently recreated.

Installation copies application-owned source and `requirements.txt` into
`/opt/prod/bmcyber`, creates or reuses the owned `.venv`, installs the
declared Python requirements, verifies the deployed service and client imports,
then creates the `bmcyber` system group when absent, writes only the named
unit, action, MyCount filter and jail files, and starts BMCyber before loading
the two owned jails. Both jails are disabled on a fresh installation.
The systemd service, Fail2ban client (including its health probe) and service-control launcher
use `/opt/prod/bmcyber/.venv/bin/python`, not system Python.
The service runs as **root**, not a dedicated account. No `bmcyber` user is
created. systemd creates `/run/bmcyber` as `root:bmcyber`, mode `0750`; a
process umask of `0117` creates the IPC socket with mode `0660` immediately.
A root-owned lock prevents a second service instance replacing the socket.
Stale sockets are removed only after acquiring that lock; unrelated files
are rejected.

The installer refuses to overwrite unowned resources or virtual environments.
Upgrade and reinstall reuse the owned `.venv`, synchronize pinned dependencies
from the deployed `requirements.txt`, and preserve production JSON, operator
data and the current MyCount jail configuration. The installed environment is recorded as
owned in `.installation-manifest.json`. `.deployment-version` advances only
after dependency installation, deployed Python validation, service startup
and a successful native IPC health probe. A failed deployment reports failure; file copying
is not a transactional rollback. Inspect or retry the checkout after failure.

Uninstall removes the owned unit, action, MyCount filter/jail and source payload,
installer-owned `.venv` and nftables table. It never deletes an unowned
virtual environment. It preserves unrelated firewall tables and Fail2ban jails,
production JSON, user data and the saved MyCount jail settings under
`conf/mycount-jails.local`. It retains the system group and its memberships.
Uninstall needs the native client when Fail2ban is running, but does not require
journal bindings or a working BMCyber venv.
An ownership manifest accounts for retained files and permits repeat uninstall
or reinstall. The last-successful version marker is removed on uninstall.

## Configure and operate

The production file is `/opt/prod/bmcyber/conf/bmcyber.json`. Missing fields
inherit constant defaults; malformed files, unknown settings, wrong types
and invalid values fail visibly. First installation generates the file from
constants only when missing. Explicit populated values are operator overrides
and remain fixed if later defaults change. Restart after editing.

| JSON setting | Default constant | Default and validation |
| --- | --- | --- |
| `ipc.socket_path` | `DZMQ.SOCKET_PATH` | `/run/bmcyber/control.sock`; a named socket directly under `/run/bmcyber`, within Linux's path-length limit. |
| `ipc.timeout_seconds` | `DZMQ.TIMEOUT_SECONDS` | `5`; finite number from `0.01` to `60`. |
| `ban.base_hours` | `DPolicy.BASE_HOURS` | `20`; finite number equivalent to at least one second. |
| `ban.random_extra_hours` | `DPolicy.RANDOM_EXTRA_HOURS` | `4`; finite nonnegative number. Base plus maximum addition cannot exceed seven days. |
| `ban.protected_ips` | `DPolicy.PROTECTED` | Loopback IPv4 and IPv6 networks; array of numeric addresses or canonical CIDR networks. |

Policy selects whole seconds from the base plus a random additional duration.
Keep the native jail's `bantime` at or below the service's minimum block
duration. If reducing `base_hours`, adjust the jail's ticket interval too,
so Fail2ban can detect fresh abuse when the kernel block expires. This native
interval does not remove enforcement entries.

Validate configuration and operate the integration in an explicit order:

```sh
/opt/prod/bmcyber/.venv/bin/python -m bmcyber --check-config --config /opt/prod/bmcyber/conf/bmcyber.json
sudo scripts/services start
sudo scripts/services restart
sudo scripts/services stop
```

Start brings up BMCyber before Fail2ban and the two MyCount jails. Stop stops
only those jails before BMCyber. Restart validates application and Fail2ban
configuration first. Unrelated Fail2ban jails remain running.
`scripts/services` always launches the installed `bmcyber.services` module with
the production venv. Its systemd interface is also used by the installer.
Add the account running any non-root action client to the `bmcyber` group and
start a new login/session for its supplementary group membership to apply.

The installed client supports:

```sh
/opt/prod/bmcyber/scripts/bmcyber-client health
/opt/prod/bmcyber/scripts/bmcyber-client ban --ip 192.0.2.10 --source operator
```

The ban command is an example using a documentation address. The client also
accepts global `--config`, `--timeout` and `--locale` options before the method.
It returns zero only after a correlated successful acknowledgement. Rejection,
missing service and timeout return nonzero. A missing reply has an uncertain
outcome: no blind retry or direct firewall fallback is performed. Human-facing
client messages use the bundled English catalogue; no translations are shipped.
Service diagnostics go to the systemd journal.

## IPC protocol

IPC uses BMForge ZMQ REQ/REP protocol version `1`, one UTF-8 JSON frame per
request and reply, with a maximum frame size of 65,536 bytes. The envelope is:

```json
{
  "protocol_version": 1,
  "sender": "bmcyber-client",
  "target": "bmcyber",
  "method": "ban",
  "payload": {"ip": "192.0.2.10", "source": "operator"}
}
```

`ban` accepts only a numeric individual IPv4/IPv6 address and a diagnostic
source token matching `[A-Za-z0-9][A-Za-z0-9_.-]{0,63}`. No duration, raw
log text, nft command, table name or source claim is accepted. `health` takes
an empty payload and performs a bounded read-only check of the owned rules.
The `target` may also be null. Unsupported methods and targets return errors.

Replies preserve the request method and address the original sender. Their
payload has `status: "ok"` or `status: "error"` with `error.code` and
`error.message`. Ban success returns the normalized `ip` and selected
`duration_seconds`. Error codes include `invalid_request`, `wrong_target`,
`unknown_method`, `enforcement_failed` and `internal_error`. Malformed requests,
including lone Unicode surrogates in nested data or keys, receive an error
without killing the worker. The IPC group is the caller authorization boundary;
`sender` and `source` are diagnostic strings, not authenticated identities.

## Firewall lifecycle

BMCyber owns only `table inet bmcyber`, marked with its ownership comment,
two timed address sets and input drop rules at priority `-10`. An existing
owned structure is verified, never flushed at startup. Other firewall tables
continue applying their normal policy. This targets host input, including
traffic to Caddy; it does not configure forwarded or container traffic.

On tested nftables 1.1.3, `add element` on an already active address refreshes
its timeout. Repeated requests therefore apply a fresh service-selected full
duration. There is no application deadline or duplicate ledger. Timeout-set
expiry restores traffic without an application cleanup loop. The adapter also
supports explicit administrative removal; there is no unban IPC method and
Fail2ban never invokes removal.

Service restarts preserve active kernel entries. A reboot loses them, and
BMCyber restores none. Native Fail2ban restored tickets may submit ordinary
fresh requests. External removal or alteration of the table makes health and
ban operations fail visibly; fix the structure and restart the service to
reinitialize it. Do not persist BMCyber's table in a saved host ruleset.

## Verification

Run the regular tests, which use temporary IPC sockets and filesystem/service
fixtures and do not modify firewall rules:

```sh
python3 -m pytest -q tests
```

In an environment permitting user/network namespaces, run the live firewall
check with the guard set to the parent namespace:

```sh
python3 - <<'PY'
import os, subprocess, sys
env = dict(os.environ, BMCYBER_PARENT_NETNS=str(os.stat('/proc/self/ns/net').st_ino))
subprocess.run(['unshare', '-Urn', sys.executable, 'tests/live_firewall.py'], env=env, check=True)
PY
```

`tests/live_permissions.py` requires root and uses only temporary sockets to
check a permitted non-root group member and an unrelated unprivileged account.
`tests/live_service.py` requires explicit private mount/network namespace guards
and root; it tests the real service entry point with temporary `/run` and group
mounts. Do not run those fixtures against an installed service.

The verified checks include native IPv4/IPv6 packet drop and expiry, repeated
insertion, explicit adapter removal, unrelated-table preservation, root service
start/stop/restart, actual IPC group permissions, malformed-message recovery,
client error status, systemd unit verification, and install/upgrade/uninstall
ownership and failure behavior using service fixtures. Application journal
detection still requires the real-host acceptance described in the
[integration guide]({{ site.baseurl }}{% link pages/mycount-integration.md %}).

Installation tests also exercise a real offline wheel install and dependency
upgrade, `pip check`, failed runtime imports, preserved success markers and
service/client/control imports with the source checkout unavailable. Host
journal preflight failure cases use fixtures; live journal access remains a
deployment acceptance check.

Before deployment, verify package versions, administrative exemptions and
complete install/upgrade/uninstall behavior on a disposable host with systemd.

---

[Documentation index]({{ site.baseurl }}{% link index.md %})

"""Run only through unshare in a fresh user+network namespace (see development guide)."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bmcyber.interface.Nftables import Nftables

if str(os.stat('/proc/self/ns/net').st_ino) == os.environ.get('BMCYBER_PARENT_NETNS') or 'BMCYBER_PARENT_NETNS' not in os.environ:
    raise SystemExit('Refusing firewall tests outside the explicitly created network namespace')


def command(*args, **kwargs):
    return subprocess.run(list(args), check=True, text=True, capture_output=True, timeout=5, **kwargs)


command('/usr/sbin/ip', 'link', 'set', 'lo', 'up')
command('/usr/sbin/nft', '-f', '-', input='add table inet sentinel\n')
firewall = Nftables()
firewall.initialize(check=True)
assert not firewall.exists()
firewall.initialize()
firewall.initialize()
for family, source, destination in ((socket.AF_INET, '192.0.2.2', '192.0.2.1'),
                                    (socket.AF_INET6, '2001:db8::2', '2001:db8::1')):
    prefix = '/32' if family == socket.AF_INET else '/128'
    for address in (source, destination):
        args = ['/usr/sbin/ip', 'addr', 'add', address + prefix, 'dev', 'lo']
        if family == socket.AF_INET6:
            args.append('nodad')
        command(*args)
    with socket.socket(family, socket.SOCK_DGRAM) as receiver, socket.socket(family, socket.SOCK_DGRAM) as sender:
        receiver.bind((destination, 0))
        receiver.settimeout(0.2)
        sender.bind((source, 0))
        target = receiver.getsockname()
        sender.sendto(b'before', target)
        assert receiver.recv(100) == b'before'
        firewall.apply(source, 2)
        firewall.initialize()  # Ordinary service restart preserves the active entry.
        sender.sendto(b'blocked', target)
        try:
            receiver.recv(100)
        except TimeoutError:
            pass
        else:
            raise AssertionError('banned source reached the input socket')
        first = firewall.inspect()
        firewall.apply(source, 10)  # Verify the native refresh behavior rather than assuming it.
        second = firewall.inspect()
        def expires(value):
            if isinstance(value, dict):
                return [value['expires']] if 'expires' in value else [n for item in value.values() for n in expires(item)]
            if isinstance(value, list):
                return [n for item in value for n in expires(item)]
            return []
        assert max(expires(second)) > max(expires(first))
        print('native repeated-add refreshed the timeout:', source)
        firewall.apply(source, 2)
        time.sleep(2.1)
        sender.sendto(b'after', target)
        assert receiver.recv(100) == b'after'
        firewall.apply(source, 30)
        firewall.remove(source)
        firewall.remove(source)
        sender.sendto(b'removed', target)
        assert receiver.recv(100) == b'removed'
        print('blocked, expired and explicitly removed:', source)
firewall.uninstall()
firewall.uninstall()
tables = json.loads(command('/usr/sbin/nft', '-j', 'list', 'tables').stdout)['nftables']
assert any(item.get('table', {}).get('name') == 'sentinel' for item in tables)
assert not firewall.exists()
print('Owned-table initialization, IPv4/IPv6 enforcement, expiry, restart, repeated insertion and isolated uninstall passed.')

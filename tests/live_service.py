"""Exercise the real root entry point in private mount and network namespaces."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from bmcyber.interface.Configuration import Configuration
from bmcyber.interface.Nftables import Nftables
from bmcyber.zmq.Client import Client

if (os.geteuid() != 0 or 'BMCYBER_PARENT_NETNS' not in os.environ
        or str(os.stat('/proc/self/ns/net').st_ino) == os.environ['BMCYBER_PARENT_NETNS']
        or str(os.stat('/proc/self/ns/mnt').st_ino) == os.environ['BMCYBER_PARENT_MNTNS']):
    raise SystemExit('Root and explicit private mount/network namespaces are required')
subprocess.run(['mount', '-t', 'tmpfs', 'tmpfs', '/run'], check=True)
with tempfile.TemporaryDirectory(prefix='bmcyber-root-service-', dir='/tmp') as folder:
    temporary = Path(folder)
    gid = os.getgid()
    groups = temporary / 'group'
    groups.write_text('\n'.join(line for line in Path('/etc/group').read_text().splitlines()
                                if not line.startswith('bmcyber:')) + f'\nbmcyber:x:{gid}:\n')
    subprocess.run(['mount', '--bind', str(groups), '/etc/group'], check=True)
    runtime = Path('/run/bmcyber')
    runtime.mkdir(mode=0o750)
    os.chown(runtime, 0, gid)
    configuration = Configuration(base_hours=10 / 3600, random_extra_hours=0, timeout_seconds=0.2)
    config = temporary / 'bmcyber.json'
    config.write_text(json.dumps({'ban': {'base_hours': configuration.base_hours, 'random_extra_hours': 0}}))
    command = [sys.executable, '-B', '-m', 'bmcyber', '--config', str(config)]
    client = Client(configuration)
    def start():
        process = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise AssertionError(process.communicate()[1].decode())
            try:
                client.request('health', {})
                return process
            except Exception:
                time.sleep(0.05)
        process.terminate()
        process.wait(timeout=5)
        raise AssertionError('service did not become healthy')
    process = start()
    try:
        client.request('ban', {'ip': '192.0.2.10', 'source': 'root-entry-test'})
    finally:
        process.terminate()
        process.wait(timeout=5)
    assert process.returncode == 0
    assert not Path(configuration.socket_path).exists()
    assert '192.0.2.10' in str(Nftables().inspect())
    process = start()
    try:
        assert '192.0.2.10' in str(Nftables().inspect())
    finally:
        process.terminate()
        process.wait(timeout=5)
    Path(configuration.socket_path).write_text('unrelated file')
    failed = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=5)
    assert failed.returncode != 0
    assert Path(configuration.socket_path).read_text() == 'unrelated file'
    print('Root service startup, health, ban, SIGTERM, restart preservation and IPC collision rejection passed.')

"""Native Fail2ban -> real IPC -> nftables test, in an isolated network namespace."""
from datetime import datetime
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from bmcyber.activity.BlockAddress import BlockAddress
from bmcyber.interface.Configuration import Configuration
from bmcyber.interface.IPCEndpoint import IPCEndpoint
from bmcyber.interface.Nftables import Nftables
from bmcyber.interface.RequestHandler import RequestHandler
from bmcyber.zmq.Server import Server

if 'BMCYBER_PARENT_NETNS' not in os.environ or str(os.stat('/proc/self/ns/net').st_ino) == os.environ['BMCYBER_PARENT_NETNS']:
    raise SystemExit('Refusing test outside an explicitly created network namespace')
package = Path(os.environ['BMCYBER_FAIL2BAN_ROOT'])
pythonpath = str(package / 'usr/lib/python3/dist-packages') + os.pathsep + str(ROOT)
environment = dict(os.environ, PYTHONPATH=pythonpath)
firewall = Nftables()
firewall.initialize()
requests = []
with tempfile.TemporaryDirectory(prefix='bmcyber-f2b-', dir='/tmp') as directory:
    temporary = Path(directory)
    configdir = temporary / 'fail2ban'
    shutil.copytree(package / 'etc/fail2ban', configdir)
    shutil.rmtree(configdir / 'jail.d')
    (configdir / 'jail.d').mkdir()
    shutil.copy(ROOT / 'fail2ban/filter.d/bmcyber-security.conf', configdir / 'filter.d')
    logs = temporary / 'mycount.log'
    logs.touch()
    ipcdir = temporary / 'ipc'
    ipcdir.mkdir(mode=0o750)
    settings = Configuration(socket_path=str(ipcdir / 'control.sock'), base_hours=6 / 3600,
                             random_extra_hours=0, timeout_seconds=2)
    # Exercise the production CLI and transport with only its deployment endpoint injected.
    client = temporary / 'client'
    client.write_text(f'''#!/usr/bin/python3
from bmcyber.interface.Configuration import Configuration
from bmcyber.client import main
Configuration.load = classmethod(lambda cls, *args, **kwargs: Configuration(socket_path={settings.socket_path!r}, timeout_seconds=2))
raise SystemExit(main())
''')
    client.chmod(0o755)
    action = (ROOT / 'fail2ban/action.d/bmcyber.conf').read_text().replace('/opt/prod/bmcyber/scripts/bmcyber-client', str(client))
    (configdir / 'action.d/bmcyber.conf').write_text(action)
    (configdir / 'jail.local').write_text(f'''[bmcyber-test]
enabled = true
backend = polling
logpath = {logs}
filter = bmcyber-security
maxretry = 1
findtime = 60
bantime = 2
usedns = no
ignoreip = 192.0.2.99
action = bmcyber[source=bmcyber-test]
''')
    (configdir / 'fail2ban.local').write_text('[Definition]\ndbfile = None\nloglevel = INFO\n')
    socketpath = temporary / 'f2b.sock'
    common = ['-c', str(configdir), '-s', str(socketpath), '-p', str(temporary / 'f2b.pid')]
    client_command = [sys.executable, str(package / 'usr/bin/fail2ban-client'), *common]
    def native(*arguments):
        return subprocess.run([*client_command, *arguments], env=environment, check=True,
                              text=True, capture_output=True, timeout=5).stdout
    def wait_for(predicate):
        until = time.monotonic() + 10
        while time.monotonic() < until:
            if predicate():
                return
            time.sleep(0.05)
        raise AssertionError('timed out waiting for native Fail2ban action')
    def emit(ip):
        with logs.open('a') as stream:
            stream.write(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + f' SECURITY event=fail2safe ip={ip}\n')
    handler = RequestHandler(BlockAddress(settings, firewall), firewall)
    def handle(message):
        requests.append(message)
        return handler(message)
    original_umask = os.umask(0o117)
    try:
        with IPCEndpoint(settings.socket_path, uid=os.geteuid(), gid=os.getegid()) as endpoint:
            with Server(settings.endpoint, handle, bound=endpoint.bound):
                with (temporary / 'daemon.log').open('w+') as output:
                    daemon = subprocess.Popen([sys.executable, str(package / 'usr/bin/fail2ban-server'),
                                               *common, '-f', '--logtarget', str(temporary / 'server.log'), 'start'],
                                              env=environment, stdout=output, stderr=output)
                    try:
                        wait_for(socketpath.exists)
                        def jail_ready():
                            try:
                                native('status', 'bmcyber-test')
                                return True
                            except subprocess.CalledProcessError:
                                return False
                        wait_for(jail_ready)
                        emit('192.0.2.99')
                        emit('192.0.2.1')
                        wait_for(lambda: len(requests) == 1)
                        time.sleep(2.6)
                        assert '192.0.2.1' not in native('get', 'bmcyber-test', 'banip')
                        assert '192.0.2.1' in str(firewall.inspect())
                        assert len(requests) == 1
                        emit('192.0.2.2')
                        wait_for(lambda: len(requests) == 2)
                        native('set', 'bmcyber-test', 'unbanip', '192.0.2.2')
                        native('stop', 'bmcyber-test')
                        assert len(requests) == 2
                        assert '192.0.2.2' in str(firewall.inspect())
                        print('Native log detection, ignoreip, IPC acknowledgement, ticket expiry, manual unban and jail stop passed.')
                    except BaseException:
                        output.seek(0)
                        print(output.read())
                        serverlog = temporary / 'server.log'
                        if serverlog.exists():
                            print(serverlog.read_text()[-6000:])
                        raise
                    finally:
                        if daemon.poll() is None:
                            try:
                                native('stop')
                            except subprocess.SubprocessError:
                                daemon.terminate()
                            daemon.wait(timeout=5)
    finally:
        os.umask(original_umask)
        firewall.uninstall()

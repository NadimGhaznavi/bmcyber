"""Disposable root-owned IPC fixture; creates no accounts or installed files."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from bmcyber.interface.Configuration import Configuration
from bmcyber.interface.IPCEndpoint import IPCEndpoint
from bmcyber.zmq.Server import Server

if os.geteuid() != 0:
    raise SystemExit('This fixture requires root to test two different unprivileged identities')
uid = int(os.environ.get('SUDO_UID', '1000'))
gid = int(os.environ.get('SUDO_GID', '1000'))
old_umask = os.umask(0o117)
old_group = os.getegid()
try:
    with tempfile.TemporaryDirectory(prefix='bmcyber-permissions-', dir='/tmp') as folder:
        directory = Path(folder)
        directory.chmod(0o711)
        ipc = directory / 'ipc'
        ipc.mkdir(mode=0o750)
        ipc.chmod(0o750)
        os.chown(ipc, 0, gid)
        configuration = Configuration(socket_path=str(ipc / 'control.sock'), timeout_seconds=0.2)
        os.setegid(gid)
        with IPCEndpoint(configuration.socket_path, uid=0, gid=gid) as endpoint:
            with Server(configuration.endpoint, lambda _: {'status': 'ok'}, bound=endpoint.bound):
                code = f'''import sys
sys.path.insert(0, {str(ROOT)!r})
from bmcyber.interface.Configuration import Configuration
from bmcyber.zmq.Client import Client
Client(Configuration(socket_path={configuration.socket_path!r}, timeout_seconds=0.2)).request('health', {{}})
'''
                def identity(user, group):
                    def set_identity():
                        os.setgroups([])
                        os.setgid(group)
                        os.setuid(user)
                    return set_identity
                allowed = subprocess.run([sys.executable, '-c', code], preexec_fn=identity(uid, gid), capture_output=True, timeout=5)
                assert allowed.returncode == 0, allowed.stderr.decode()
                denied = subprocess.run([sys.executable, '-c', code], preexec_fn=identity(65534, 65534), capture_output=True, timeout=5)
                assert denied.returncode != 0
                assert (ipc / 'control.sock').stat().st_uid == 0
                print('A non-root group member connected; an unrelated unprivileged identity was denied.')
finally:
    os.setegid(old_group)
    os.umask(old_umask)

"""Single-host systemd/Fail2ban provisioning used by the existing installer."""
import grp
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from bmcyber.constants.DBMCyber import DBMCyber
from bmcyber.constants.DZMQ import DZMQ
from bmcyber.constants.DPolicy import DPolicy
from bmcyber.interface.Configuration import Configuration
from bmcyber.interface.Nftables import Nftables


class ServiceInstallation:
    RESOURCES = {
        'systemd/bmcyber.service': 'etc/systemd/system/bmcyber.service',
        'fail2ban/filter.d/bmcyber-security.conf': 'etc/fail2ban/filter.d/bmcyber-security.conf',
        'fail2ban/action.d/bmcyber.conf': 'etc/fail2ban/action.d/bmcyber.conf',
        'fail2ban/jail.d/bmcyber-mycount.local': 'etc/fail2ban/jail.d/bmcyber-mycount.local',
    }
    OWNERSHIP = '.service-resources.json'
    JAIL = 'bmcyber-mycount'
    RETAINED_JAIL = 'conf/bmcyber-mycount.local'

    def __init__(self, checkout, destination, *, root=Path('/'), run=subprocess.run, which=shutil.which, firewall=None):
        self.checkout = Path(checkout)
        self.destination = Path(destination)
        self.root = Path(root)
        self.run = run
        self.which = which
        self.firewall = firewall or Nftables()

    def command(self, *arguments):
        return self.run(list(arguments), check=True, text=True, capture_output=True, timeout=30)

    def owned(self):
        marker = self.destination / self.OWNERSHIP
        self.safe(marker)
        if not marker.exists():
            return []
        names = json.loads(marker.read_text())
        if not isinstance(names, list) or set(names) != set(self.RESOURCES.values()):
            raise ValueError('invalid service resource ownership record')
        return names

    @staticmethod
    def safe(path):
        for item in (path, *path.parents):
            if item.is_symlink():
                raise ValueError(f'symlink in service deployment path: {item}')

    def preflight(self, action):
        owned = self.owned()
        if action == 'uninstall' and not owned:
            return
        required = ('systemctl', DPolicy.NFT_EXECUTABLE, 'fail2ban-client')
        if action != 'uninstall':
            required += ('/usr/bin/python3',)
            try:
                grp.getgrnam(DZMQ.GROUP)
            except KeyError:
                required += ('groupadd',)
            self.safe(self.destination / DBMCyber.CONFIG_FILE)
            Configuration.load(self.destination / DBMCyber.CONFIG_FILE)
        for executable in required:
            if self.which(executable) is None:
                raise ValueError(f'missing required executable: {executable}')
        if action != 'uninstall':
            self.command('/usr/bin/python3', '-c', 'import zmq; print(zmq.__version__)')
        for original, relative in self.RESOURCES.items():
            target = self.root / relative
            self.safe(target)
            if target.exists() and (not target.is_file() or relative not in owned):
                raise ValueError(f'refusing an unowned service resource: {target}')
            if action != 'uninstall' and not (self.checkout / original).is_file():
                raise ValueError(f'missing service source: {original}')
        if action != 'uninstall':
            self.firewall.initialize(check=True)
            self.command('fail2ban-client', '-t')
        elif owned and self.firewall.exists():
            self.firewall.inspect()

    @staticmethod
    def atomic_write(path, content):
        ServiceInstallation.safe(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix='.bmcyber-', dir=path.parent)
        try:
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(content)
                os.fchmod(stream.fileno(), 0o644)
            os.replace(temporary, path)
        finally:
            Path(temporary).unlink(missing_ok=True)

    def stop(self):
        if not self.owned():
            return
        state = self.run(['systemctl', 'is-active', '--quiet', 'fail2ban.service'],
                         check=False, text=True, capture_output=True, timeout=30)
        if state.returncode == 0:
            status = self.run(['fail2ban-client', 'status', self.JAIL],
                              check=False, text=True, capture_output=True, timeout=30)
            if status.returncode == 0:
                self.command('fail2ban-client', 'stop', self.JAIL)
            else:
                self.command('fail2ban-client', 'ping')
        elif state.returncode != 3:
            raise ValueError('cannot determine the Fail2ban service state')
        self.command('systemctl', 'stop', 'bmcyber.service')

    def configure(self):
        try:
            grp.getgrnam(DZMQ.GROUP)
        except KeyError:
            self.command('groupadd', '--system', DZMQ.GROUP)
        configuration = self.destination / DBMCyber.CONFIG_FILE
        if not configuration.exists():
            self.atomic_write(configuration, (json.dumps(Configuration.defaults(), indent=2) + '\n').encode())
        self.atomic_write(self.destination / self.OWNERSHIP,
                          (json.dumps(list(self.RESOURCES.values()), indent=2) + '\n').encode())
        for original, relative in self.RESOURCES.items():
            target = self.root / relative
            if original.endswith('.local'):
                if target.exists():
                    continue
                retained = self.destination / self.RETAINED_JAIL
                content = retained.read_bytes() if retained.exists() else (self.checkout / original).read_bytes()
            else:
                content = (self.checkout / original).read_bytes()
            self.atomic_write(target, content)
        self.command('systemctl', 'daemon-reload')
        self.command('fail2ban-client', '-t')

    def start(self):
        self.command('systemctl', 'enable', '--now', 'bmcyber.service')
        self.command('systemctl', 'start', 'fail2ban.service')
        self.command('fail2ban-client', 'reload', '--if-exists', self.JAIL)

    def health(self):
        self.command(str(self.destination / 'scripts/bmcyber-client'), 'health')

    def uninstall(self):
        owned = self.owned()
        if not owned:
            return
        self.stop()
        jail = self.root / self.RESOURCES['fail2ban/jail.d/bmcyber-mycount.local']
        if jail.exists():
            self.atomic_write(self.destination / self.RETAINED_JAIL, jail.read_bytes())
            jail.unlink()
        self.command('systemctl', 'disable', '--now', 'bmcyber.service')
        self.firewall.uninstall()
        for relative in owned:
            (self.root / relative).unlink(missing_ok=True)
        self.command('systemctl', 'daemon-reload')
        (self.destination / self.OWNERSHIP).unlink()

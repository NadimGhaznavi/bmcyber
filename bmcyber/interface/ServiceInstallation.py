"""Single-host systemd/Fail2ban provisioning used by the existing installer."""
import grp
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from bmcyber.constants.DBMCyber import DBMCyber
from bmcyber.constants.DInstallation import DInstallation, InstallationAction
from bmcyber.constants.DService import DService
from bmcyber.constants.DZMQ import DZMQ
from bmcyber.constants.DPolicy import DPolicy
from bmcyber.interface.Configuration import Configuration
from bmcyber.interface.Nftables import Nftables
from bmcyber.interface.ServiceControl import ServiceControl


class ServiceInstallation:
    RESOURCES = dict(DInstallation.SERVICE_RESOURCES)
    OWNERSHIP = DInstallation.SERVICE_OWNERSHIP

    def __init__(self, checkout, destination, *, root=Path('/'), run=subprocess.run, which=shutil.which, firewall=None):
        self.checkout = Path(checkout)
        self.destination = Path(destination)
        self.root = Path(root)
        self.run = run
        self.which = which
        self.firewall = firewall or Nftables()
        self.control = ServiceControl(run=run)

    def command(self, *arguments):
        return self.run(list(arguments), check=True, text=True, capture_output=True,
                        timeout=DInstallation.COMMAND_TIMEOUT)

    def owned(self):
        marker = self.destination / self.OWNERSHIP
        self.safe(marker)
        if not marker.exists():
            return []
        names = json.loads(marker.read_text())
        if (not isinstance(names, list) or not all(isinstance(name, str) for name in names)
                or len(names) != len(set(names)) or set(names) != set(self.RESOURCES.values())):
            raise ValueError('invalid service resource ownership record')
        return names

    @staticmethod
    def safe(path):
        for item in (path, *path.parents):
            if item.is_symlink():
                raise ValueError(f'symlink in service deployment path: {item}')

    def preflight(self, action):
        owned = self.owned()
        if action == InstallationAction.UNINSTALL and not owned:
            return
        required = (DService.SYSTEMCTL, DPolicy.NFT_EXECUTABLE)
        if action != InstallationAction.UNINSTALL:
            required += (DService.FAIL2BAN_CLIENT, DService.FAIL2BAN_SERVER)
            try:
                grp.getgrnam(DZMQ.GROUP)
            except KeyError:
                required += (DService.GROUPADD,)
            self.safe(self.destination / DBMCyber.CONFIG_FILE)
            Configuration.load(self.destination / DBMCyber.CONFIG_FILE)
        for executable in required:
            if self.which(executable) is None:
                raise ValueError(f'missing required executable: {executable}')
        for original, relative in self.RESOURCES.items():
            target = self.root / relative
            self.safe(target)
            if target.exists() and (not target.is_file() or relative not in owned):
                raise ValueError(f'refusing an unowned service resource: {target}')
            if action != InstallationAction.UNINSTALL and not (self.checkout / original).is_file():
                raise ValueError(f'missing service source: {original}')
        if action != InstallationAction.UNINSTALL:
            self.check_journal()
            self.firewall.initialize(check=True)
            self.command(DService.FAIL2BAN_CLIENT, '-t')
        elif owned and self.firewall.exists():
            self.firewall.inspect()

    def check_journal(self):
        # Support the distribution's host interpreter explicitly; never probe
        # journal bindings in BMCyber's venv or guess an alternative interpreter.
        server = Path(self.which(DService.FAIL2BAN_SERVER))
        with server.open() as stream:
            interpreter = stream.readline().removeprefix('#!').strip()
        if interpreter != DInstallation.SYSTEM_PYTHON:
            raise ValueError(f'Fail2ban must use the host interpreter {DInstallation.SYSTEM_PYTHON}')
        self.command(DInstallation.SYSTEM_PYTHON, '-I', '-B', '-c',
                     'from systemd import journal\n'
                     'with journal.Reader(flags=journal.LOCAL_ONLY | journal.SYSTEM) as reader:\n'
                     '    if not (reader.has_runtime_files() or reader.has_persistent_files()):\n'
                     '        raise RuntimeError("No readable system journal; check Fail2ban host journal access")\n'
                     '    reader.seek_tail()\n'
                     '    reader.get_previous()\n')

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
        self.control.stop()

    def configure(self):
        try:
            grp.getgrnam(DZMQ.GROUP)
        except KeyError:
            self.command(DService.GROUPADD, '--system', DZMQ.GROUP)
        configuration = self.destination / DBMCyber.CONFIG_FILE
        if not configuration.exists():
            self.atomic_write(configuration, (json.dumps(Configuration.defaults(), indent=2) + '\n').encode())
        self.atomic_write(self.destination / self.OWNERSHIP,
                          (json.dumps(list(self.RESOURCES.values()), indent=2) + '\n').encode())
        for original, relative in self.RESOURCES.items():
            target = self.root / relative
            self.atomic_write(target, (self.checkout / original).read_bytes())
        self.control.reload()
        self.command(DService.FAIL2BAN_CLIENT, '-t')

    def start(self):
        self.control.start(enable=True)

    def health(self):
        self.command(str(self.destination / DInstallation.CLIENT_LAUNCHER), 'health')

    def uninstall(self):
        owned = self.owned()
        if not owned:
            return
        self.stop()
        self.control.disable()
        self.firewall.uninstall()
        for relative in owned:
            (self.root / relative).unlink(missing_ok=True)
        self.control.reload()
        (self.destination / self.OWNERSHIP).unlink()

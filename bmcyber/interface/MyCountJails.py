"""Native controls for BMCyber's two owned MyCount jails only."""
import subprocess

from bmcyber.constants.DFail2ban import DFail2ban
from bmcyber.constants.DInstallation import DInstallation
from bmcyber.constants.DService import DService


class MyCountJails:
    def __init__(self, *, run=subprocess.run):
        self.run = run

    def command(self, *arguments, check=True):
        return self.run(list(arguments), check=check, text=True,
                        capture_output=True, timeout=DInstallation.COMMAND_TIMEOUT)

    def running(self):
        result = self.command(DService.SYSTEMCTL, 'is-active', '--quiet', DFail2ban.UNIT, check=False)
        if result.returncode not in (0, DFail2ban.INACTIVE):
            raise ValueError('Cannot determine the Fail2ban service state')
        return result.returncode == 0

    def check(self):
        self.command(DFail2ban.CLIENT, '-t')

    def start(self):
        self.command(DService.SYSTEMCTL, 'start', DFail2ban.UNIT)
        for jail in DFail2ban.JAILS:
            self.command(DFail2ban.CLIENT, 'reload', '--if-exists', jail)

    def stop(self):
        if not self.running():
            return
        for jail in DFail2ban.JAILS:
            status = self.command(DFail2ban.CLIENT, 'status', jail, check=False)
            if status.returncode == 0:
                self.command(DFail2ban.CLIENT, 'stop', jail)
            else:
                # A disabled/absent owned jail is normal. A failed daemon is not.
                self.command(DFail2ban.CLIENT, 'ping')


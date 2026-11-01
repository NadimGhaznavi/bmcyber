"""Interface to the owned systemd unit, shared by deployment and the CLI."""
import subprocess

from bmcyber.constants.DInstallation import DInstallation
from bmcyber.constants.DService import DService
from bmcyber.interface.MyCountJails import MyCountJails


class ServiceControl:
    def __init__(self, *, run=subprocess.run):
        self.run = run
        self.jails = MyCountJails(run=run)

    def command(self, *arguments):
        return self.run([DService.SYSTEMCTL, *arguments], check=True, text=True,
                        capture_output=True, timeout=DInstallation.COMMAND_TIMEOUT)

    def start(self, *, enable=False):
        if enable:
            self.command('enable', '--now', DService.UNIT)
        else:
            self.command('start', DService.UNIT)
        self.jails.start()

    def stop(self):
        self.jails.stop()
        self.command('stop', DService.UNIT)

    def disable(self):
        self.command('disable', '--now', DService.UNIT)

    def reload(self):
        self.command('daemon-reload')


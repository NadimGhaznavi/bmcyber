import subprocess

import pytest

from bmcyber import services
from bmcyber.interface.Configuration import Configuration
from bmcyber.interface.ServiceControl import ServiceControl
from bmcyber.constants.DFail2ban import DFail2ban


CHECK = ['fail2ban-client', '-t']
START_JAILS = [['systemctl', 'start', 'fail2ban.service']] + [
    ['fail2ban-client', 'reload', '--if-exists', jail] for jail in DFail2ban.JAILS]
STOP_JAILS = [['systemctl', 'is-active', '--quiet', 'fail2ban.service']]
for jail in DFail2ban.JAILS:
    STOP_JAILS += [['fail2ban-client', 'status', jail], ['fail2ban-client', 'stop', jail]]


@pytest.mark.parametrize('action,expected', [
    ('start', [CHECK, ['systemctl', 'start', 'bmcyber.service'], *START_JAILS]),
    ('stop', [*STOP_JAILS, ['systemctl', 'stop', 'bmcyber.service']]),
    ('restart', [CHECK, *STOP_JAILS, ['systemctl', 'stop', 'bmcyber.service'],
                 ['systemctl', 'start', 'bmcyber.service'], *START_JAILS]),
])
def test_cli_uses_shared_control_with_explicit_order(monkeypatch, action, expected):
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0)

    control = ServiceControl(run=run)
    monkeypatch.setattr(services, 'ServiceControl', lambda: control)
    monkeypatch.setattr(Configuration, 'load', lambda: calls.append('validated'))
    assert services.main([action]) == 0
    assert calls == (['validated'] if action != 'stop' else []) + expected


def test_invalid_configuration_prevents_stopping_and_failed_stop_prevents_start(monkeypatch, capsys):
    calls = []

    def failed_command(command, **kwargs):
        calls.append(command)
        if command == ['systemctl', 'stop', 'bmcyber.service']:
            raise subprocess.CalledProcessError(1, command, stderr='unit stop failed')
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(services, 'ServiceControl', lambda: ServiceControl(run=failed_command))

    def bad_configuration():
        raise ValueError('invalid policy')

    monkeypatch.setattr(Configuration, 'load', bad_configuration)
    assert services.main(['restart']) == 1
    assert calls == []
    assert 'invalid policy' in capsys.readouterr().err
    monkeypatch.setattr(Configuration, 'load', lambda: None)
    assert services.main(['restart']) == 1
    assert calls == [CHECK, *STOP_JAILS, ['systemctl', 'stop', 'bmcyber.service']]
    assert 'unit stop failed' in capsys.readouterr().err


def test_absent_jails_are_accepted_but_daemon_failure_prevents_service_stop():
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 1 if command[1] == 'status' else 0)

    control = ServiceControl(run=run)
    control.stop()
    assert sum(command == ['fail2ban-client', 'ping'] for command in calls) == 2
    assert not any(command[:2] == ['fail2ban-client', 'stop'] for command in calls)

    def failed_ping(command, **kwargs):
        if command == ['fail2ban-client', 'ping']:
            raise subprocess.CalledProcessError(1, command)
        return run(command, **kwargs)

    calls.clear()
    control = ServiceControl(run=failed_ping)
    with pytest.raises(subprocess.CalledProcessError):
        control.stop()
    assert ['systemctl', 'stop', 'bmcyber.service'] not in calls

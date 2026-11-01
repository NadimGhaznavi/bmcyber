import subprocess

import pytest

from bmcyber import services
from bmcyber.interface.Configuration import Configuration
from bmcyber.interface.ServiceControl import ServiceControl


@pytest.mark.parametrize('action,expected', [
    ('start', [['systemctl', 'start', 'bmcyber.service']]),
    ('stop', [['systemctl', 'stop', 'bmcyber.service']]),
    ('restart', [['systemctl', 'stop', 'bmcyber.service'], ['systemctl', 'start', 'bmcyber.service']]),
])
def test_cli_uses_shared_control_with_explicit_order(monkeypatch, action, expected):
    calls = []
    control = ServiceControl(run=lambda command, **kwargs: calls.append(command))
    monkeypatch.setattr(services, 'ServiceControl', lambda: control)
    monkeypatch.setattr(Configuration, 'load', lambda: calls.append('validated'))
    assert services.main([action]) == 0
    assert calls == (['validated'] if action != 'stop' else []) + expected


def test_invalid_configuration_prevents_stopping_and_failed_stop_prevents_start(monkeypatch, capsys):
    calls = []

    def failed_command(command, **kwargs):
        calls.append(command)
        raise subprocess.CalledProcessError(1, command, stderr='unit stop failed')

    monkeypatch.setattr(services, 'ServiceControl', lambda: ServiceControl(run=failed_command))

    def bad_configuration():
        raise ValueError('invalid policy')

    monkeypatch.setattr(Configuration, 'load', bad_configuration)
    assert services.main(['restart']) == 1
    assert calls == []
    assert 'invalid policy' in capsys.readouterr().err
    monkeypatch.setattr(Configuration, 'load', lambda: None)
    assert services.main(['restart']) == 1
    assert calls == [['systemctl', 'stop', 'bmcyber.service']]
    assert 'unit stop failed' in capsys.readouterr().err

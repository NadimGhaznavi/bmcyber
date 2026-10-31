import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from ServiceInstallation import ServiceInstallation

spec = importlib.util.spec_from_file_location('installer', ROOT / 'scripts/install.py')
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class Firewall:
    def __init__(self):
        self.present = False
        self.checked = False

    def initialize(self, *, check=False):
        self.checked = check

    def exists(self):
        return self.present

    def inspect(self):
        return {}

    def uninstall(self):
        self.present = False


@pytest.fixture
def deployment(tmp_path):
    destination = tmp_path / 'prod'
    calls = []
    def run(arguments, **kwargs):
        calls.append(arguments)
        return subprocess.CompletedProcess(arguments, 0, stdout='ok', stderr='')
    firewall = Firewall()
    host = ServiceInstallation(ROOT, destination, root=tmp_path / 'host', run=run,
                               which=lambda executable: executable, firewall=firewall)
    installation = installer.Installation(ROOT, destination=destination, host=host)
    return installation, host, calls


def test_check_is_read_only_and_missing_dependency_precedes_changes(deployment):
    installation, host, calls = deployment
    installation.apply('install', check=True)
    assert not installation.destination.exists()
    assert host.firewall.checked
    assert not any(call[0] in ('systemctl', 'groupadd') for call in calls)
    host.which = lambda name: None if name == 'fail2ban-client' else name
    for check in (True, False):
        with pytest.raises(ValueError, match='fail2ban-client'):
            installation.apply('install', check=check)
        assert not installation.destination.exists()


def test_install_reinstall_upgrade_uninstall_and_reinstall_preserve_operator_data(deployment):
    installation, host, calls = deployment
    installation.apply('install')
    base = installation.destination
    assert (base / '.deployment-version').read_text().strip() == '0.0.0'
    assert (base / 'bmcyber/constants/DBMCyber.py').is_file()
    assert calls.index(['systemctl', 'enable', '--now', 'bmcyber.service']) < calls.index(['systemctl', 'start', 'fail2ban.service'])
    configuration = base / 'conf/bmcyber.json'
    data = json.loads(configuration.read_text())
    data['ban']['base_hours'] = 21
    configuration.write_text(json.dumps(data))
    jail = host.root / host.RESOURCES['fail2ban/jail.d/bmcyber-mycount.local']
    jail.write_text(jail.read_text().replace('/var/log/mycount/mycount.log', '/operator/mycount.log'))
    unrelated = host.root / 'etc/fail2ban/jail.d/unrelated.local'
    unrelated.write_text('[unrelated]\nenabled = false\n')
    (base / 'operator-notes.txt').write_text('keep me')
    installation.apply('install')
    installation.apply('upgrade')
    assert json.loads(configuration.read_text())['ban']['base_hours'] == 21
    assert '/operator/mycount.log' in jail.read_text()
    installation.apply('uninstall')
    installation.apply('uninstall')
    assert unrelated.exists()
    assert (base / 'operator-notes.txt').read_text() == 'keep me'
    assert configuration.exists()
    assert '/operator/mycount.log' in (base / host.RETAINED_JAIL).read_text()
    assert not (base / '.deployment-version').exists()
    assert not jail.exists()
    installation.apply('install')
    assert '/operator/mycount.log' in jail.read_text()
    assert json.loads(configuration.read_text())['ban']['base_hours'] == 21


def test_invalid_configuration_and_unowned_resources_fail_before_stopping(deployment):
    installation, host, calls = deployment
    target = host.root / 'etc/systemd/system/bmcyber.service'
    target.parent.mkdir(parents=True)
    target.write_text('unowned')
    with pytest.raises(ValueError, match='unowned'):
        installation.apply('install')
    assert target.read_text() == 'unowned'
    assert not installation.destination.exists()
    target.unlink()
    installation.apply('install')
    configuration = installation.destination / 'conf/bmcyber.json'
    configuration.write_text('{"ban":{"base_hours":0}}')
    calls.clear()
    with pytest.raises(ValueError):
        installation.apply('upgrade')
    assert not any(call[:2] == ['systemctl', 'stop'] for call in calls)
    # Uninstall must still work when retained configuration is invalid.
    installation.apply('uninstall')
    assert configuration.exists()


def test_failed_activation_never_advances_success_marker(deployment):
    installation, host, _ = deployment
    def failed_health():
        raise subprocess.CalledProcessError(1, 'health')
    host.health = failed_health
    with pytest.raises(subprocess.CalledProcessError):
        installation.apply('install')
    assert not (installation.destination / '.deployment-version').exists()
    assert (installation.destination / '.installation-manifest.json').exists()
    installation.apply('uninstall')


def test_symlink_and_manifest_escape_rejected(deployment, tmp_path):
    installation, host, _ = deployment
    outside = tmp_path / 'outside'
    outside.mkdir()
    target = host.root / 'etc/systemd'
    target.parent.mkdir(parents=True)
    target.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match='symlink'):
        installation.apply('install')
    assert not installation.destination.exists()
    with pytest.raises(ValueError):
        installer.relative_path('../outside')


def test_disabled_jail_and_empty_enforcement_removal_hooks():
    import configparser
    jail = configparser.ConfigParser(interpolation=None)
    jail.read(ROOT / 'fail2ban/jail.d/bmcyber-mycount.local')
    assert not jail['bmcyber-mycount'].getboolean('enabled')
    action = configparser.ConfigParser(interpolation=None)
    action.read(ROOT / 'fail2ban/action.d/bmcyber.conf')
    for hook in ('actionunban', 'actionstop', 'actionflush'):
        assert action['Definition'][hook] == ''
    assert '<matches>' not in action['Definition']['actionban']
    assert '<bantime>' not in action['Definition']['actionban']


def test_upgrade_stops_only_owned_jail_before_service(deployment):
    installation, host, calls = deployment
    installation.apply('install')
    calls.clear()
    installation.apply('upgrade')
    assert calls.index(['fail2ban-client', 'stop', 'bmcyber-mycount']) < calls.index(['systemctl', 'stop', 'bmcyber.service'])
    assert ['systemctl', 'stop', 'fail2ban.service'] not in calls
    assert ['fail2ban-client', 'reload'] not in calls

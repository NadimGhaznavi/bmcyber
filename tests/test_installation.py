import json
import os
from pathlib import Path
import shutil
import subprocess
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
from bmcyber.constants.DInstallation import DInstallation
from bmcyber.constants.DService import DService
from bmcyber.interface.Installation import Installation, relative_path
from bmcyber.interface.ServiceInstallation import ServiceInstallation


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
    venv = destination / DInstallation.VENV_DIR

    def run(arguments, **kwargs):
        calls.append(arguments)
        if arguments[:3] == [DInstallation.SYSTEM_PYTHON, '-m', 'venv']:
            assert arguments[3] == str(venv)
            (venv / 'bin').mkdir(parents=True, exist_ok=True)
            (venv / 'bin/python').write_text('test interpreter')
            (venv / 'pyvenv.cfg').write_text('home = /usr/bin\n')
        elif arguments[0] == str(venv / 'bin/python'):
            assert (arguments[1:3] == ['-m', 'pip']
                    or arguments[1:3] == ['-B', '-c']
                    or arguments[1:4] == ['-I', '-B', '-c']
                    or arguments[1:4] in (['-B', '-m', 'bmcyber'], ['-B', '-m', 'bmcyber.client']))
            assert kwargs['cwd'] == destination
            assert 'PYTHONPATH' not in kwargs['env']
            assert kwargs['env']['PYTHONNOUSERSITE'] == '1'
            assert (venv / 'bin/python').is_file()
        elif arguments[0] == str(destination / 'scripts/bmcyber-client'):
            assert (venv / 'bin/python').is_file()
        elif arguments[0] == DInstallation.SYSTEM_PYTHON:
            assert arguments[1:4] == ['-I', '-B', '-c']
        else:
            assert arguments[0] in ('systemctl', 'fail2ban-client', 'groupadd'), arguments
        return subprocess.CompletedProcess(arguments, 0, stdout='ok', stderr='')

    server = tmp_path / 'fail2ban-server'
    server.write_text('#! /usr/bin/python3\n')
    firewall = Firewall()
    host = ServiceInstallation(ROOT, destination, root=tmp_path / 'host', run=run,
                               which=lambda executable: str(server) if executable == DService.FAIL2BAN_SERVER else executable,
                               firewall=firewall)
    installation = Installation(ROOT, destination=destination, host=host, run=run)
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
    assert (base / '.deployment-version').read_text().strip() == installation.metadata['VERSION']
    assert (base / '.venv/bin/python').is_file()
    assert json.loads((base / '.installation-manifest.json').read_text())['venv_owned']
    assert (base / 'bmcyber/constants/DBMCyber.py').is_file()
    assert ['systemctl', 'enable', '--now', 'bmcyber.service'] in calls
    configuration = base / 'conf/bmcyber.json'
    data = json.loads(configuration.read_text())
    data['ban']['base_hours'] = 21
    configuration.write_text(json.dumps(data))
    unrelated = host.root / 'etc/fail2ban/jail.d/unrelated.local'
    unrelated.parent.mkdir(parents=True)
    unrelated.write_text('[unrelated]\nenabled = false\n')
    (base / 'operator-notes.txt').write_text('keep me')
    installation.apply('install')
    installation.apply('upgrade')
    assert calls.count([DInstallation.SYSTEM_PYTHON, '-m', 'venv', str(base / '.venv')]) == 1
    assert sum(command[1:4] == ['-m', 'pip', 'install'] for command in calls) == 3
    assert json.loads(configuration.read_text())['ban']['base_hours'] == 21
    installation.apply('uninstall')
    installation.apply('uninstall')
    assert unrelated.exists()
    assert (base / 'operator-notes.txt').read_text() == 'keep me'
    assert configuration.exists()
    assert not (base / '.deployment-version').exists()
    assert not (base / '.venv').exists()
    installation.apply('install')
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
        relative_path('../outside')


def test_empty_enforcement_removal_hooks():
    import configparser
    action = configparser.ConfigParser(interpolation=None)
    action.read(ROOT / 'fail2ban/action.d/bmcyber.conf')
    for hook in ('actionunban', 'actionstop', 'actionflush'):
        assert action['Definition'][hook] == ''
    assert '<matches>' not in action['Definition']['actionban']
    assert '<bantime>' not in action['Definition']['actionban']


def test_service_lifecycle_leaves_fail2ban_running(deployment):
    installation, host, calls = deployment
    installation.apply('install')
    calls.clear()
    installation.apply('upgrade')
    assert ['systemctl', 'stop', 'bmcyber.service'] in calls
    installation.apply('uninstall')
    assert not any(command[:2] in (['fail2ban-client', 'stop'], ['fail2ban-client', 'reload'])
                   or command[0] == 'systemctl' and 'fail2ban.service' in command for command in calls)


def test_venv_preflight_and_dry_run_are_read_only(deployment):
    installation, host, calls = deployment
    installation.apply('install', check=True)
    assert not installation.destination.exists()
    assert [DInstallation.SYSTEM_PYTHON, '-I', '-B', '-c', 'import venv, ensurepip'] in calls
    assert not any('-m' in cmd and 'pip' in cmd for cmd in calls)
    assert not any(cmd[1:3] == ['-m', 'venv'] for cmd in calls)
    installation.apply('install')
    calls.clear()
    installation.apply('upgrade', check=True)
    assert not any(cmd[1:3] == ['-m', 'venv'] for cmd in calls)
    assert not any('pip' in cmd for cmd in calls)


@pytest.mark.parametrize('check', [True, False])
@pytest.mark.parametrize('failure', ['missing journal bindings', 'system journal is not readable'])
def test_journal_preflight_fails_before_host_or_file_changes(deployment, check, failure):
    installation, host, calls = deployment
    normal_run = host.run

    def fail_journal(command, **kwargs):
        if '-c' in command and 'from systemd import journal' in command[-1]:
            calls.append(command)
            raise subprocess.CalledProcessError(1, command, stderr=failure)
        return normal_run(command, **kwargs)

    host.run = fail_journal
    with pytest.raises(subprocess.CalledProcessError) as error:
        installation.apply('install', check=check)
    assert error.value.stderr == failure
    assert not installation.destination.exists()
    assert not any(command[0] in ('systemctl', 'groupadd') for command in calls)


def test_journal_preflight_checks_fail2ban_interpreter_and_uninstall_needs_no_fail2ban(deployment):
    installation, host, calls = deployment
    server = Path(host.which(DService.FAIL2BAN_SERVER))
    server.write_text('#!/opt/dev/mycount/.venv/bin/python\n')
    with pytest.raises(ValueError, match='Fail2ban must use the host interpreter'):
        installation.apply('install', check=True)
    assert not installation.destination.exists()
    server.write_text('#! /usr/bin/python3\n')
    installation.apply('install')
    host.which = lambda executable: None if executable in (DService.FAIL2BAN_CLIENT, DService.FAIL2BAN_SERVER) else executable
    calls.clear()
    installation.apply('uninstall')
    assert not any(command[0] in (DService.FAIL2BAN_CLIENT, DService.FAIL2BAN_SERVER) for command in calls)


@pytest.mark.parametrize('damage', ['missing-config', 'missing-python', 'development-home', 'global-packages'])
def test_damaged_owned_environment_is_rejected_before_stopping(deployment, damage):
    installation, host, calls = deployment
    installation.apply('install')
    marker = installation.destination / DInstallation.VERSION_MARKER
    before = marker.stat().st_mtime_ns
    venv = installation.destination / DInstallation.VENV_DIR
    if damage == 'missing-config':
        (venv / 'pyvenv.cfg').unlink()
    elif damage == 'missing-python':
        (venv / 'bin/python').unlink()
    elif damage == 'development-home':
        (venv / 'pyvenv.cfg').write_text('home = /opt/dev/mycount/.venv/bin\n')
    else:
        (venv / 'pyvenv.cfg').write_text('include-system-site-packages = true\n')
    for check in (True, False):
        calls.clear()
        with pytest.raises(ValueError, match='Production virtual environment'):
            installation.apply('upgrade', check=check)
        assert not any(command[0] == 'systemctl' for command in calls)
        assert marker.stat().st_mtime_ns == before
    installation.apply('uninstall')
    assert not venv.exists()


@pytest.mark.parametrize('entry', ['-e ./package', '-e./package', '--editable=./package',
                                  'dependency @ file:///opt/dev/package'])
def test_development_requirements_are_rejected_without_mutation(deployment, tmp_path, entry):
    installation, _, calls = deployment
    checkout = tmp_path / 'source'
    checkout.mkdir()
    for tree in DInstallation.COPY_TREES:
        shutil.copytree(ROOT / tree, checkout / tree, ignore=shutil.ignore_patterns('__pycache__'))
    (checkout / DInstallation.REQUIREMENTS_FILE).write_text(entry + '\n')
    installation.checkout = checkout
    for check in (True, False):
        with pytest.raises(ValueError, match='must not use editable or /opt/dev'):
            installation.apply('install', check=check)
    assert not installation.destination.exists()
    assert calls == []


@pytest.mark.parametrize('phase', ['pip-check', 'runtime-import'])
def test_python_validation_failure_preserves_marker_and_prevents_activation(deployment, phase):
    installation, _, calls = deployment
    installation.apply('install')
    marker = installation.destination / DInstallation.VERSION_MARKER
    before = marker.stat().st_mtime_ns
    normal_run = installation.run

    def fail_validation(command, **kwargs):
        if ((phase == 'pip-check' and command[1:4] == ['-m', 'pip', 'check'])
                or (phase == 'runtime-import' and command[1:3] == ['-B', '-c'])):
            raise subprocess.CalledProcessError(1, command)
        return normal_run(command, **kwargs)

    installation.run = fail_validation
    calls.clear()
    with pytest.raises(subprocess.CalledProcessError):
        installation.apply('upgrade')
    assert marker.stat().st_mtime_ns == before
    assert not any(command[:2] == ['systemctl', 'enable'] for command in calls)


def test_python_environment_does_not_inherit_development_or_user_site_settings(deployment, monkeypatch):
    installation, _, _ = deployment
    for key in ('PYTHONPATH', 'PYTHONHOME', 'VIRTUAL_ENV', 'PIP_TARGET', 'PIP_PREFIX', 'PIP_USER'):
        monkeypatch.setenv(key, '/opt/dev/example')
    environment = installation.python_environment()
    assert environment['PYTHONNOUSERSITE'] == '1'
    assert not any(key in environment for key in ('PYTHONPATH', 'PYTHONHOME', 'VIRTUAL_ENV',
                                                  'PIP_TARGET', 'PIP_PREFIX', 'PIP_USER'))


def test_pip_failure_retains_old_version_and_owned_venv_for_retry(deployment):
    installation, _, calls = deployment
    installation.apply('install')
    original_version = (installation.destination / '.deployment-version').read_text()
    original_run = installation.run

    def fail_pip(command, **kwargs):
        if command[1:4] == ['-m', 'pip', 'install']:
            raise subprocess.CalledProcessError(1, command)
        return original_run(command, **kwargs)

    installation.run = fail_pip
    with pytest.raises(subprocess.CalledProcessError):
        installation.apply('upgrade')
    assert (installation.destination / '.deployment-version').read_text() == original_version
    assert (installation.destination / '.venv/bin/python').is_file()
    assert json.loads((installation.destination / '.installation-manifest.json').read_text())['venv_owned']
    assert not any(cmd[:2] == ['systemctl', 'enable'] for cmd in calls[-3:])
    installation.run = original_run
    installation.apply('upgrade')
    assert (installation.destination / '.deployment-version').read_text() == original_version


def test_failed_first_dependency_install_can_be_uninstalled(deployment):
    installation, _, _ = deployment
    normal_run = installation.run

    def fail_install(command, **kwargs):
        if command[1:4] == ['-m', 'pip', 'install']:
            raise subprocess.CalledProcessError(1, command)
        return normal_run(command, **kwargs)

    installation.run = fail_install
    with pytest.raises(subprocess.CalledProcessError):
        installation.apply('install')
    assert not (installation.destination / '.deployment-version').exists()
    assert (installation.destination / '.venv').is_dir()
    installation.apply('uninstall')
    assert not (installation.destination / '.venv').exists()


def test_unowned_environment_is_never_replaced_or_removed(deployment):
    installation, _, _ = deployment
    installation.apply('install')
    manifest = installation.destination / '.installation-manifest.json'
    record = json.loads(manifest.read_text())
    record['venv_owned'] = False
    manifest.write_text(json.dumps(record))
    with pytest.raises(ValueError, match='unowned virtual environment'):
        installation.apply('upgrade', check=True)
    assert (installation.destination / '.venv').exists()
    installation.apply('uninstall')
    assert (installation.destination / '.venv').exists()


def test_production_launchers_never_use_global_python():
    unit = (ROOT / 'systemd/bmcyber.service').read_text()
    launcher = (ROOT / 'scripts/bmcyber-client').read_text()
    services_launcher = (ROOT / 'scripts/services').read_text()
    action = (ROOT / 'fail2ban/action.d/bmcyber.conf').read_text()
    assert 'ExecStart=/opt/prod/bmcyber/.venv/bin/python -B -m bmcyber' in unit
    assert 'cd /opt/prod/bmcyber' in launcher
    assert 'exec /opt/prod/bmcyber/.venv/bin/python -B -m bmcyber.client' in launcher
    assert 'exec /opt/prod/bmcyber/.venv/bin/python -B -m bmcyber.services' in services_launcher
    assert '/usr/bin/python3' not in unit + launcher + services_launcher
    assert '/opt/prod/bmcyber/scripts/bmcyber-client' in action


def test_real_venv_imports_deployed_app_without_source_checkout(tmp_path, monkeypatch):
    """Use an offline dummy pyzmq wheel to test installation mechanics, not ZeroMQ."""
    checkout = tmp_path / 'source'
    checkout.mkdir()
    for tree in DInstallation.COPY_TREES:
        shutil.copytree(ROOT / tree, checkout / tree,
                        ignore=shutil.ignore_patterns('__pycache__', '.venv', '*.pyc'))
    for name in DInstallation.COPY_FILES:
        shutil.copy2(ROOT / name, checkout / name)
    wheels = tmp_path / 'wheels'
    wheels.mkdir()

    def wheel(version):
        dist = f'pyzmq-{version}.dist-info'
        with zipfile.ZipFile(wheels / f'pyzmq-{version}-py3-none-any.whl', 'w') as archive:
            archive.writestr('zmq/__init__.py', f'__version__ = "{version}"\nclass ZMQError(Exception): pass\n')
            archive.writestr(f'{dist}/METADATA', f'Metadata-Version: 2.1\nName: pyzmq\nVersion: {version}\n')
            archive.writestr(f'{dist}/WHEEL', 'Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n')
            archive.writestr(f'{dist}/RECORD', '')

    wheel('26.4.0')
    monkeypatch.setenv('PIP_NO_INDEX', '1')
    monkeypatch.setenv('PIP_FIND_LINKS', str(wheels))
    destination = tmp_path / 'deployed'
    activations = []

    class NoHost:
        def preflight(self, _): pass
        def stop(self): pass
        def configure(self): pass
        def start(self): activations.append('start')
        def health(self): pass
        def uninstall(self): pass

    installation = Installation(checkout, destination=destination, host=NoHost())
    prerequisites = subprocess.run([DInstallation.SYSTEM_PYTHON, '-I', '-B', '-c', 'import venv, ensurepip'],
                                   capture_output=True, text=True)
    if prerequisites.returncode:
        pytest.skip(f'Python venv unavailable: {prerequisites.stderr}')
    installation.apply('install', check=True)
    installation.apply('install')
    assert activations == ['start']
    wheel('26.4.1')
    (checkout / DInstallation.REQUIREMENTS_FILE).write_text('pyzmq==26.4.1\n')
    installation.apply('upgrade')
    python = destination / '.venv/bin/python'
    installed_version = subprocess.run([str(python), '-B', '-c', 'import zmq; print(zmq.__version__)'],
                                       cwd=destination, check=True, text=True, capture_output=True)
    assert installed_version.stdout.strip() == '26.4.1'
    assert activations == ['start', 'start']
    marker = destination / DInstallation.VERSION_MARKER
    before = marker.stat().st_mtime_ns
    with monkeypatch.context() as context:
        context.setattr(DInstallation, 'RUNTIME_IMPORTS', (*DInstallation.RUNTIME_IMPORTS, 'bmcyber.missing_module'))
        with pytest.raises(subprocess.CalledProcessError):
            installation.apply('upgrade')
    assert marker.stat().st_mtime_ns == before
    assert activations == ['start', 'start']
    checkout.rename(tmp_path / 'offline-source')
    environment = os.environ.copy()
    environment.pop('PYTHONPATH', None)
    environment.pop('PYTHONHOME', None)
    probe = subprocess.run([str(python), '-c',
                            'import sys, zmq, bmcyber.__main__; '
                            'print(sys.prefix); print(zmq.__file__); '
                            'print(bmcyber.__main__.__file__)'],
                           cwd=destination, env=environment, check=True, text=True,
                           capture_output=True)
    prefix, dependency, application = probe.stdout.strip().splitlines()
    assert Path(prefix).resolve() == (destination / '.venv').resolve()
    assert Path(dependency).is_relative_to(destination / '.venv')
    assert Path(application).is_relative_to(destination / 'bmcyber')
    subprocess.run([str(python), '-m', 'bmcyber', '--check-config',
                    '--config', str(destination / 'conf/bmcyber.json')],
                   cwd=destination, env=environment, check=True, capture_output=True)
    subprocess.run([str(python), '-B', '-m', 'bmcyber.client', '--help'],
                   cwd=destination, env=environment, check=True, capture_output=True)
    subprocess.run([str(python), '-B', '-m', 'bmcyber.services', '--help'],
                   cwd=destination, env=environment, check=True, capture_output=True)
    installation.apply('uninstall')
    assert not (destination / '.venv').exists()

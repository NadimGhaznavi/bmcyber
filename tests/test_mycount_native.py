"""Native parser/counter/action checks using synthetic journal records.

Set BMCYBER_FAIL2BAN_ROOT to an extracted distribution package (or / for an
installed package). This never starts Fail2ban, reads the host journal or calls
nftables. Real MyCount/systemd delivery requires the documented host acceptance.
"""
from datetime import datetime
import os
from pathlib import Path
import shutil
import sys
import time
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

import pytest

from bmcyber.constants.DFail2ban import DFail2ban


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope='module')
def native(tmp_path_factory):
    location = os.environ.get('BMCYBER_FAIL2BAN_ROOT')
    if not location:
        pytest.skip('Set BMCYBER_FAIL2BAN_ROOT for native Fail2ban checks')
    package = Path(location)
    sys.path.insert(0, str(package / 'usr/lib/python3/dist-packages'))
    from fail2ban.client.jailsreader import JailsReader
    from fail2ban.server.filter import Filter
    from fail2ban.server.failmanager import FailManagerEmpty
    from fail2ban.server.mytime import MyTime
    from fail2ban.server.action import CommandAction

    # Only the formatter is used: no substitute reader or watcher is run.
    systemd = ModuleType('systemd')
    systemd.journal = ModuleType('systemd.journal')
    systemd.journal.__version__ = '999'
    with patch.dict(sys.modules, {'systemd': systemd, 'systemd.journal': systemd.journal}):
        from fail2ban.server.filtersystemd import FilterSystemd

    directory = tmp_path_factory.mktemp('native-fail2ban') / 'configuration'
    shutil.copytree(package / 'etc/fail2ban', directory)
    shutil.rmtree(directory / 'jail.d')
    (directory / 'jail.d').mkdir()
    for source in (ROOT / 'fail2ban').rglob('*'):
        if source.is_file():
            target = directory / source.relative_to(ROOT / 'fail2ban')
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes())
    jail = directory / 'jail.d/bmcyber-mycount.local'
    jail.write_text(jail.read_text().replace('enabled = false', 'enabled = true'))
    reader = JailsReader(basedir=str(directory))
    assert reader.read()
    assert reader.getOptions()
    commands = reader.convert()

    def options(name):
        return {command[2]: command[3:] for command in commands if command[:2] == ['set', name]}

    def filter_for(name):
        config = options(name)
        queued = []
        jail = SimpleNamespace(name=name, putFailTicket=queued.append, queued=queued)
        result = Filter(jail, useDns='no')
        result.setMaxRetry(config['maxretry'][0])
        result.setFindTime(config['findtime'][0])
        result.addFailRegex(config['addfailregex'][0])
        for address in config['addignoreip']:
            result.addIgnoreIP(address)
        return result

    def record(event, ip, *, epoch=None, pid=100, message=None):
        epoch = time.time() if epoch is None else epoch
        stamp = datetime.fromtimestamp(epoch)
        metadata = {
            '_HOSTNAME': 'fixture-host', 'SYSLOG_IDENTIFIER': 'python', '_PID': pid,
            '__REALTIME_TIMESTAMP': stamp,
            'MESSAGE': message if message is not None else
                stamp.strftime('%Y-%m-%d %H:%M:%S') + f' SECURITY event={event} ip={ip}',
        }
        formatter = SimpleNamespace(getLogEncoding=lambda: 'utf-8', jailName='fixture',
            getJrnEntTime=lambda item: (stamp.isoformat(), epoch))
        return FilterSystemd.formatJournalEntry(formatter, metadata)

    yield SimpleNamespace(commands=commands, options=options, filter=filter_for, record=record,
                          empty=FailManagerEmpty, clock=MyTime, action=CommandAction)
    MyTime.setTime(None)
    sys.path.remove(str(package / 'usr/lib/python3/dist-packages'))


def test_native_configuration_is_unit_scoped_and_uses_ban_only_action(native):
    for name, event, threshold in DFail2ban.RULES:
        options = native.options(name)
        assert ['add', name, 'systemd'] in native.commands
        assert options['addjournalmatch'] == ['_SYSTEMD_UNIT=' + DFail2ban.MYCOUNT_UNIT]
        assert int(options['maxretry'][0]) == threshold
        assert int(options['findtime'][0]) == DFail2ban.FINDTIME
        assert not any(command[:3] == ['set', name, 'addlogpath'] for command in native.commands)
        action = next(command for command in native.commands if command[:3] == ['multi-set', name, 'action'])
        parameters = dict(action[4])
        assert parameters['source'] == name
        assert all(parameters[hook] == '' for hook in ('actionunban', 'actionstop', 'actionflush'))


@pytest.mark.parametrize('ip', ['192.0.2.10', '2001:db8::10'])
def test_native_thresholds_combine_workers_and_keep_events_separate(native, ip):
    for name, event, threshold in DFail2ban.RULES:
        filter = native.filter(name)
        for index in range(threshold - 1):
            filter.processLineAndAdd(*native.record(event, ip, pid=100 + index % 3))
        assert filter.jail.queued == []
        with pytest.raises(native.empty):
            filter.failManager.toBan()
        other = 'malformed_payload' if event == 'collection_request' else 'collection_request'
        filter.processLineAndAdd(*native.record(other, ip))
        with pytest.raises(native.empty):
            filter.failManager.toBan()
        filter.processLineAndAdd(*native.record(event, ip, pid=103))
        assert [str(ticket.getIP()) for ticket in filter.jail.queued] == [ip]


def test_native_time_window_and_exemptions(native):
    now = time.time()
    try:
        native.clock.setTime(now)
        filter = native.filter(DFail2ban.MALFORMED)
        for _ in range(4):
            filter.processLineAndAdd(*native.record('malformed_payload', '192.0.2.11', epoch=now))
        native.clock.setTime(now + 61)
        filter.failManager.cleanup(now + 61)
        filter.processLineAndAdd(*native.record('malformed_payload', '192.0.2.11', epoch=now + 61))
        with pytest.raises(native.empty):
            filter.failManager.toBan()
        assert filter.jail.queued == []
        for ip in ('127.0.0.9', '::1'):
            for _ in range(5):
                filter.processLineAndAdd(*native.record('malformed_payload', ip, epoch=now + 61))
            with pytest.raises(native.empty):
                filter.failManager.toBan()
            assert filter.jail.queued == []
    finally:
        native.clock.setTime(None)


@pytest.mark.parametrize('suffix', [
    'SECURITY event=fail2safe ip=192.0.2.10',
    'SECURITY event=malformed_payload ip=192.0.2.10 extra=attacker',
    'WARNING SECURITY event=malformed_payload ip=192.0.2.10',
    'SECURITY event=malformed_payload ip=example.org',
    'SECURITY event=malformed_payload ip=fe80::1%eth0',
    'SECURITY event=malformed_payload ip=192.0.2.10\nSECURITY event=malformed_payload ip=192.0.2.20',
])
def test_native_match_rejects_unrelated_or_forged_content(native, suffix):
    message = datetime.now().strftime('%Y-%m-%d %H:%M:%S') + ' ' + suffix
    filter = native.filter(DFail2ban.MALFORMED)
    assert filter.processLine(*native.record('', '', message=message)) == []


def test_native_action_uses_real_cli_and_ipc_without_unban_or_retry(native, tmp_path, monkeypatch):
    from bmcyber.activity.BlockAddress import BlockAddress
    from bmcyber.interface.Configuration import Configuration
    from bmcyber.interface.IPCEndpoint import IPCEndpoint
    from bmcyber.interface.RequestHandler import RequestHandler
    from bmcyber.zmq.Server import Server

    calls = []
    requests = []

    class Firewall:
        def inspect(self): return {}
        def apply(self, ip, seconds): calls.append(ip)

    ipc = tmp_path / 'ipc'
    ipc.mkdir(mode=0o750)
    settings = Configuration(socket_path=str(ipc / 'control.sock'), timeout_seconds=0.1)
    launcher = tmp_path / 'client'
    launcher.write_text(f'#!{sys.executable}\n'
        'from bmcyber.interface.Configuration import Configuration\n'
        'from bmcyber.client import main\n'
        f'Configuration.load = classmethod(lambda cls, *args, **kwargs: Configuration(socket_path={settings.socket_path!r}, timeout_seconds=0.1))\n'
        'raise SystemExit(main())\n')
    launcher.chmod(0o755)
    monkeypatch.setenv('PYTHONPATH', str(ROOT))
    monkeypatch.setenv('PYTHONDONTWRITEBYTECODE', '1')
    config = next(command for command in native.commands
                  if command[:3] == ['multi-set', DFail2ban.MALFORMED, 'action'])
    action = native.action(None, 'bmcyber')
    for key, value in config[4]:
        setattr(action, key, value.replace('/opt/prod/bmcyber/scripts/bmcyber-client', str(launcher)))
    firewall = Firewall()
    request_handler = RequestHandler(BlockAddress(settings, firewall), firewall)

    def handler(message):
        requests.append(message.payload)
        return request_handler(message)
    old_umask = os.umask(0o117)
    try:
        with IPCEndpoint(settings.socket_path, uid=os.geteuid(), gid=os.getegid()) as endpoint:
            with Server(settings.endpoint, handler, bound=endpoint.bound) as server:
                action.ban({'ip': '192.0.2.30'})
                assert calls == ['192.0.2.30']
                assert requests == [{'ip': '192.0.2.30', 'source': DFail2ban.MALFORMED}]
                action.unban({'ip': '192.0.2.30'})
                action.stop()
                assert calls == ['192.0.2.30']
                with pytest.raises(RuntimeError, match='Error banning'):
                    action.ban({'ip': '127.0.0.1'})
                assert calls == ['192.0.2.30']

                def delayed(message):
                    result = handler(message)
                    time.sleep(0.3)
                    return result

                server.handler = delayed
                with pytest.raises(RuntimeError, match='Error banning'):
                    action.ban({'ip': '192.0.2.31'})
                assert calls == ['192.0.2.30', '192.0.2.31']
        with pytest.raises(RuntimeError, match='Error banning'):
            action.ban({'ip': '192.0.2.32'})
        assert calls == ['192.0.2.30', '192.0.2.31']
    finally:
        os.umask(old_umask)

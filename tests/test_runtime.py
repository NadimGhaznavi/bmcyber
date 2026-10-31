import json
import os
from pathlib import Path
import socket
import subprocess
import time

import pytest
import zmq

from bmcyber.activity.BlockAddress import BlockAddress
from bmcyber.constants.DPolicy import DPolicy
from bmcyber.constants.DText import DText
from bmcyber.constants.DZMQ import DZMQ, Method
from bmcyber.entity.BanRequest import BanRequest
from bmcyber.interface.Configuration import Configuration
from bmcyber.interface.IPCEndpoint import IPCEndpoint
from bmcyber.interface.Localizer import Localizer
from bmcyber.interface.Nftables import Nftables
from bmcyber.interface.RequestHandler import RequestHandler
from bmcyber.zmq.Client import Client
from bmcyber.zmq.Message import Message
from bmcyber.zmq.Server import Server

ROOT = Path(__file__).resolve().parents[1]


class Firewall:
    def __init__(self):
        self.calls = []
        self.failure = None

    def inspect(self):
        if self.failure:
            raise self.failure
        return {}

    def apply(self, ip, seconds):
        self.inspect()
        self.calls.append((ip, seconds))


@pytest.fixture
def running(tmp_path):
    directory = tmp_path / 'ipc'
    directory.mkdir(mode=0o750)
    configuration = Configuration(socket_path=str(directory / 'control.sock'), timeout_seconds=0.2)
    firewall = Firewall()
    handler = RequestHandler(BlockAddress(configuration, firewall), firewall)
    old_umask = os.umask(DZMQ.SERVICE_UMASK)
    try:
        with IPCEndpoint(configuration.socket_path, uid=os.geteuid(), gid=os.getegid()) as endpoint:
            with Server(configuration.endpoint, handler, bound=endpoint.bound) as server:
                yield configuration, firewall, server
    finally:
        os.umask(old_umask)


def exchange(configuration, frames):
    with zmq.Context() as context:
        with context.socket(zmq.REQ) as client:
            client.setsockopt(zmq.LINGER, 0)
            client.setsockopt(zmq.RCVTIMEO, 1000)
            client.connect(configuration.endpoint)
            client.send_multipart(frames)
            return Message.from_json(client.recv())


def test_real_ipc_ban_and_health(running):
    configuration, firewall, _ = running
    result = Client(configuration).request(Method.BAN, {'ip': '192.0.2.1', 'source': 'mycount'})
    assert result['status'] == 'ok'
    assert 72000 <= result['duration_seconds'] <= 86400
    assert firewall.calls == [('192.0.2.1', result['duration_seconds'])]
    assert Client(configuration).request(Method.HEALTH, {}) == {'status': 'ok'}
    assert Path(configuration.socket_path).stat().st_mode & 0o777 == 0o660
    assert Path(configuration.socket_path).parent.stat().st_mode & 0o777 == 0o750


@pytest.mark.parametrize('frames', [
    [b'not-json'], [b'{}'], [b'[]'], [b'{}', b'{}'],
    [b'{"protocol_version":true,"sender":"test","target":null,"method":"health","payload":{}}'],
    [b'{"protocol_version":99,"sender":"test","target":null,"method":"health","payload":{}}'],
    [b'{"protocol_version":1,"sender":"\\ud800","target":null,"method":"health","payload":{}}'],
    [b'{"protocol_version":1,"sender":"test","target":null,"method":"\\udfff","payload":{}}'],
    [b'{"protocol_version":1,"sender":"test","target":null,"method":"health","payload":{"nested":[{"\\ud800":"value"}]}}'],
    [b'{"protocol_version":1,"sender":"test","target":null,"method":"health","payload":{"nested":["\\udfff"]}}'],
])
def test_bad_then_good_on_same_server(running, frames):
    configuration, _, server = running
    reply = exchange(configuration, frames)
    assert reply.payload['error']['code'] == 'invalid_request'
    assert Client(configuration).request(Method.HEALTH, {})['status'] == 'ok'
    server.check()


def test_surrogate_pair_and_application_errors(running):
    configuration, firewall, _ = running
    good = json.dumps(json.loads(Message('test-\U0001f600', 'health', target='bmcyber').to_json()), ensure_ascii=True).encode()
    assert exchange(configuration, [good]).payload['status'] == 'ok'
    for message, code in ((Message('test', 'unknown'), 'unknown_method'),
                          (Message('test', 'health', target='another'), 'wrong_target'),
                          (Message('test', 'health', payload={'unexpected': True}), 'invalid_request')):
        assert exchange(configuration, [message.to_json()]).payload['error']['code'] == code
    firewall.failure = subprocess.TimeoutExpired('nft', 5)
    with pytest.raises(ValueError, match='enforcement_failed'):
        Client(configuration).request(Method.BAN, {'ip': '192.0.2.1', 'source': 'mycount'})
    firewall.failure = None
    assert Client(configuration).request(Method.HEALTH, {})['status'] == 'ok'


def test_handler_failure_has_reply_and_worker_survives(running):
    configuration, _, server = running
    original = server.handler
    def fail(_):
        raise RuntimeError('test handler failure')
    server.handler = fail
    assert exchange(configuration, [Message('test', 'health').to_json()]).payload['error']['code'] == 'internal_error'
    server.handler = original
    assert Client(configuration).request(Method.HEALTH, {})['status'] == 'ok'


def test_ipc_duplicate_owner_cannot_replace_socket(running):
    configuration, _, _ = running
    inode = Path(configuration.socket_path).stat().st_ino
    with pytest.raises(BlockingIOError):
        with IPCEndpoint(configuration.socket_path, uid=os.geteuid(), gid=os.getegid()):
            pytest.fail('duplicate endpoint acquired')
    assert Path(configuration.socket_path).stat().st_ino == inode
    assert Client(configuration).request(Method.HEALTH, {})['status'] == 'ok'


def test_stale_socket_regular_file_and_directory_permissions(tmp_path):
    directory = tmp_path / 'ipc'
    directory.mkdir(mode=0o750)
    path = directory / 'control.sock'
    native = socket.socket(socket.AF_UNIX)
    native.bind(str(path))
    native.close()
    with IPCEndpoint(path, uid=os.geteuid(), gid=os.getegid()):
        assert not path.exists()
    path.write_text('unrelated')
    with pytest.raises(ValueError, match='unrelated'):
        with IPCEndpoint(path, uid=os.geteuid(), gid=os.getegid()):
            pass
    assert path.read_text() == 'unrelated'
    directory.chmod(0o770)
    with pytest.raises(ValueError, match='0750'):
        with IPCEndpoint(path, uid=os.geteuid(), gid=os.getegid()):
            pass


def test_missing_service_timeout_is_bounded_and_socket_is_discarded(tmp_path):
    configuration = Configuration(socket_path=str(tmp_path / 'absent.sock'), timeout_seconds=0.05)
    started = time.monotonic()
    for _ in range(2):
        with pytest.raises(zmq.Again):
            Client(configuration).request(Method.HEALTH, {})
    assert time.monotonic() - started < 1


@pytest.mark.parametrize('ip', ['example.org', '192.0.2.1/24', '::1%lo', '1.2.3.4;id', '[::1]', '1.2.3.4:80'])
def test_reject_invalid_ban_addresses(ip):
    with pytest.raises(ValueError):
        BanRequest(ip, 'mycount')


def test_source_validation_and_protection():
    for source in ('bad source', 'bad;source', '../foo', '', 'x' * 65):
        with pytest.raises(ValueError):
            BanRequest('192.0.2.1', source)
    firewall = Firewall()
    blocking = BlockAddress(Configuration(), firewall)
    with pytest.raises(ValueError, match='protected'):
        blocking.execute(BanRequest('127.0.0.1', 'mycount'))
    assert not firewall.calls


def test_duration_extremes_are_seconds_and_not_tracked():
    class FixedRandom:
        def randint(self, lower, upper):
            return upper
    firewall = Firewall()
    blocking = BlockAddress(Configuration(), firewall, random=FixedRandom())
    request = BanRequest('2001:db8::1', 'mycount')
    assert blocking.execute(request) == 86400
    assert blocking.execute(request) == 86400
    assert len(firewall.calls) == 2


@pytest.mark.parametrize('data', [[], {'unknown': {}}, {'ban': {'unknown': 1}},
    {'ban': {'base_hours': True}}, {'ban': {'base_hours': 0}},
    {'ban': {'random_extra_hours': -1}}, {'ban': {'base_hours': float('nan')}},
    {'ban': {'base_hours': 168, 'random_extra_hours': 1}},
    {'ipc': {'timeout_seconds': 'five'}}, {'ipc': {'socket_path': 'tcp://localhost:80'}},
    {'ipc': {'socket_path': '/run/bmcyber/*'}}, {'ipc': {'socket_path': '/run/bmcyber/service.lock'}}, {'ban': {'protected_ips': ['bad']}}])
def test_configuration_rejects_invalid_values_before_overrides(tmp_path, data):
    path = tmp_path / 'config.json'
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match=str(path)):
        Configuration.load(path, timeout_seconds=1)


def test_configuration_defaults_partial_override_and_explicit_timeout(tmp_path):
    path = tmp_path / 'config.json'
    assert Configuration.load(path).base_hours == 20
    path.write_text('{"ban":{"base_hours":21},"ipc":{"timeout_seconds":2}}')
    configuration = Configuration.load(path, timeout_seconds=3)
    assert configuration.base_hours == 21
    assert configuration.random_extra_hours == 4
    assert configuration.timeout_seconds == 3
    assert configuration.endpoint == 'ipc:///run/bmcyber/control.sock'
    path.write_text('{')
    with pytest.raises(ValueError):
        Configuration.load(path)


def test_localizer_is_canonical_and_catalogue_matches_keys():
    assert (ROOT / 'bmcyber/interface/Localizer.py').read_bytes() == (ROOT / '.agents/skills/bmforge-localization/assets/Localizer.py').read_bytes()
    assert set(json.loads((ROOT / 'bmcyber/locales/en.json').read_text())) == {key.value for key in DText}
    localizer = Localizer(ROOT / 'bmcyber/locales')
    assert localizer.select(explicit='zh-CN') == 'en'
    assert localizer.text(DText.CHECKED) == 'BMCyber configuration is valid.'


def test_nft_rejects_bad_values_before_invoking_command():
    calls = []
    nft = Nftables(run=lambda *a, **k: calls.append((a, k)))
    for seconds in (0, -1, float('inf'), True, 604801):
        with pytest.raises(ValueError):
            nft.apply('192.0.2.1', seconds)
    with pytest.raises(ValueError):
        nft.apply('::1%lo', 30)
    assert calls == []


def test_action_cli_success_and_failure_exit_status(running, monkeypatch, capsys):
    from bmcyber.client import main
    configuration, firewall, _ = running
    monkeypatch.setattr(Configuration, 'load', classmethod(lambda cls, *args, **kwargs: configuration))
    assert main(['ban', '--ip', '192.0.2.10', '--source', 'mycount']) == 0
    assert 'acknowledged ban' in capsys.readouterr().out
    firewall.failure = subprocess.TimeoutExpired('nft', 5)
    assert main(['ban', '--ip', '192.0.2.10', '--source', 'mycount']) == 1
    assert 'failed' in capsys.readouterr().err
    assert main(['ban', '--ip', '192.0.2.10;id', '--source', 'mycount']) == 1
    assert 'failed' in capsys.readouterr().err
    firewall.failure = None


def test_checked_in_configuration_matches_generated_defaults():
    assert json.loads((ROOT / 'conf/bmcyber.json').read_text()) == Configuration.defaults()


def test_lost_acknowledgement_fails_without_repeating_applied_ban(running, monkeypatch, capsys):
    from bmcyber.client import main
    configuration, firewall, server = running
    original = server.handler
    def delayed_reply(message):
        result = original(message)
        time.sleep(0.3)
        return result
    server.handler = delayed_reply
    monkeypatch.setattr(Configuration, 'load', classmethod(lambda cls, *args, **kwargs: configuration))
    assert main(['ban', '--ip', '192.0.2.20', '--source', 'mycount']) == 1
    assert 'failed' in capsys.readouterr().err
    assert len(firewall.calls) == 1
    server.handler = original

"""One resolver for service, action client and deployment tools."""
from dataclasses import dataclass
import ipaddress
import json
import math
from pathlib import Path

from bmcyber.constants.DBMCyber import DBMCyber
from bmcyber.constants.DPolicy import DPolicy
from bmcyber.constants.DZMQ import DZMQ


@dataclass(frozen=True)
class Configuration:
    socket_path: str = DZMQ.SOCKET_PATH
    timeout_seconds: float = DZMQ.TIMEOUT_SECONDS
    base_hours: float = DPolicy.BASE_HOURS
    random_extra_hours: float = DPolicy.RANDOM_EXTRA_HOURS
    protected_ips: tuple[str, ...] = DPolicy.PROTECTED

    @property
    def endpoint(self):
        return 'ipc://' + self.socket_path

    @classmethod
    def defaults(cls):
        return {
            'ipc': {'socket_path': DZMQ.SOCKET_PATH, 'timeout_seconds': DZMQ.TIMEOUT_SECONDS},
            'ban': {'base_hours': DPolicy.BASE_HOURS, 'random_extra_hours': DPolicy.RANDOM_EXTRA_HOURS,
                    'protected_ips': list(DPolicy.PROTECTED)},
        }

    @classmethod
    def load(cls, path=None, *, timeout_seconds=None):
        path = Path(path or Path(DBMCyber.BASE_DIR) / DBMCyber.CONFIG_FILE)
        values = cls.defaults()
        try:
            data = json.loads(path.read_text(encoding='utf-8'))
        except FileNotFoundError:
            data = {}
        except (OSError, ValueError) as error:
            raise ValueError(f'{path}: {error}') from error
        try:
            if not isinstance(data, dict) or set(data) - set(values):
                raise ValueError('expected only ipc and ban objects')
            for group, entries in data.items():
                if not isinstance(entries, dict) or set(entries) - set(values[group]):
                    raise ValueError(f'unknown or invalid {group} settings')
                values[group].update(entries)
            ipc, ban = values['ipc'], values['ban']
            socket_path = ipc['socket_path']
            if (not isinstance(socket_path, str) or '\0' in socket_path or '*' in socket_path
                    or Path(socket_path).parent != Path(DZMQ.RUNTIME_DIRECTORY)
                    or Path(socket_path).name in ('', '.', '..', 'service.lock')
                    or len(socket_path.encode('utf-8')) > DZMQ.MAX_PATH_BYTES):
                raise ValueError('ipc.socket_path must name a socket directly under /run/bmcyber')
            for key, value, minimum, maximum in (
                ('ipc.timeout_seconds', ipc['timeout_seconds'], 0.01, 60),
                ('ban.base_hours', ban['base_hours'], 1 / DPolicy.SECONDS_PER_HOUR, DPolicy.MAX_SECONDS / DPolicy.SECONDS_PER_HOUR),
                ('ban.random_extra_hours', ban['random_extra_hours'], 0, DPolicy.MAX_SECONDS / DPolicy.SECONDS_PER_HOUR),
            ):
                if type(value) not in (int, float) or not math.isfinite(value) or not minimum <= value <= maximum:
                    raise ValueError(f'{key} must be finite and between {minimum} and {maximum}')
            if (ban['base_hours'] + ban['random_extra_hours']) * DPolicy.SECONDS_PER_HOUR > DPolicy.MAX_SECONDS:
                raise ValueError('ban duration must not exceed seven days')
            protected = ban['protected_ips']
            if not isinstance(protected, list) or not all(isinstance(item, str) for item in protected):
                raise ValueError('ban.protected_ips must be an array of IP addresses or networks')
            for item in protected:
                ipaddress.ip_network(item)
            if timeout_seconds is not None:
                if not math.isfinite(timeout_seconds) or not 0.01 <= timeout_seconds <= 60:
                    raise ValueError('timeout override must be between 0.01 and 60 seconds')
                ipc['timeout_seconds'] = timeout_seconds
            return cls(socket_path, ipc['timeout_seconds'], ban['base_hours'], ban['random_extra_hours'], tuple(protected))
        except (ValueError, TypeError, UnicodeError) as error:
            raise ValueError(f'{path}: {error}') from error

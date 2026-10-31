"""The IPC-only request/reply protocol."""
from typing import Final
from enum import StrEnum


class DZMQ:
    PROTOCOL_VERSION: Final[int] = 1
    SERVICE: Final[str] = 'bmcyber'
    SOCKET_PATH: Final[str] = '/run/bmcyber/control.sock'
    RUNTIME_DIRECTORY: Final[str] = '/run/bmcyber'
    GROUP: Final[str] = 'bmcyber'
    DIRECTORY_MODE: Final[int] = 0o750
    SOCKET_MODE: Final[int] = 0o660
    SERVICE_UMASK: Final[int] = 0o117
    TIMEOUT_SECONDS: Final[int] = 5
    POLL_MS: Final[int] = 100
    MAX_MESSAGE_BYTES: Final[int] = 65536
    MAX_PATH_BYTES: Final[int] = 107
    FIELDS: Final[tuple[str, ...]] = ('protocol_version', 'sender', 'target', 'method', 'payload')
    VERSION: Final[str] = 'protocol_version'
    SENDER: Final[str] = 'sender'
    TARGET: Final[str] = 'target'
    METHOD: Final[str] = 'method'
    PAYLOAD: Final[str] = 'payload'
    STATUS: Final[str] = 'status'
    ERROR: Final[str] = 'error'
    CODE: Final[str] = 'code'
    MESSAGE: Final[str] = 'message'
    OK: Final[str] = 'ok'
    IP: Final[str] = 'ip'
    SOURCE: Final[str] = 'source'
    DURATION: Final[str] = 'duration_seconds'


class Method(StrEnum):
    BAN = 'ban'
    HEALTH = 'health'


class ErrorCode(StrEnum):
    INVALID_REQUEST = 'invalid_request'
    UNKNOWN_METHOD = 'unknown_method'
    WRONG_TARGET = 'wrong_target'
    ENFORCEMENT_FAILED = 'enforcement_failed'
    INTERNAL_ERROR = 'internal_error'

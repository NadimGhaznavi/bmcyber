"""Adapted BMForge versioned envelope with recursive Unicode validation."""
from dataclasses import dataclass, field
import json
from typing import Any

from bmcyber.constants.DZMQ import DZMQ


def unicode_scalars(value):
    if isinstance(value, str):
        value.encode('utf-8')
    elif isinstance(value, dict):
        for key, item in value.items():
            unicode_scalars(key)
            unicode_scalars(item)
    elif isinstance(value, list):
        for item in value:
            unicode_scalars(item)


@dataclass
class Message:
    sender: str
    method: str
    target: str | None = None
    payload: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        for value in (self.sender, self.method):
            if not isinstance(value, str) or not value.strip():
                raise ValueError('sender and method must be nonempty strings')
        if self.target is not None and not isinstance(self.target, str):
            raise ValueError('target must be a string or null')
        if not isinstance(self.payload, dict):
            raise ValueError('payload must be an object')
        unicode_scalars([self.sender, self.method, self.target, self.payload])

    def to_json(self):
        return json.dumps({
            DZMQ.VERSION: DZMQ.PROTOCOL_VERSION, DZMQ.SENDER: self.sender,
            DZMQ.METHOD: self.method, DZMQ.TARGET: self.target, DZMQ.PAYLOAD: self.payload,
        }, ensure_ascii=False, allow_nan=False).encode('utf-8')

    @classmethod
    def from_json(cls, frame):
        if len(frame) > DZMQ.MAX_MESSAGE_BYTES:
            raise ValueError('message exceeds size limit')
        data = json.loads(frame.decode('utf-8'), parse_constant=lambda _: invalid_number())
        if not isinstance(data, dict) or set(data) != set(DZMQ.FIELDS):
            raise ValueError('invalid envelope fields')
        if type(data[DZMQ.VERSION]) is not int or data[DZMQ.VERSION] != DZMQ.PROTOCOL_VERSION:
            raise ValueError('unsupported protocol version')
        return cls(sender=data[DZMQ.SENDER], method=data[DZMQ.METHOD],
                   target=data[DZMQ.TARGET], payload=data[DZMQ.PAYLOAD])


def invalid_number():
    raise ValueError('non-finite JSON number')

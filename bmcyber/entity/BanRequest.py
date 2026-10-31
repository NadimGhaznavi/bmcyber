"""Validated request values; no transport or enforcement state."""
from dataclasses import dataclass
import ipaddress
import re

from bmcyber.constants.DPolicy import DPolicy


@dataclass(frozen=True)
class BanRequest:
    ip: str
    source: str

    def __post_init__(self):
        if not isinstance(self.ip, str) or '%' in self.ip:
            raise ValueError('ip must be a numeric IPv4 or IPv6 address without a zone')
        object.__setattr__(self, 'ip', str(ipaddress.ip_address(self.ip)))
        if not isinstance(self.source, str) or not re.fullmatch(DPolicy.SOURCE_PATTERN, self.source):
            raise ValueError('source must be a safe identifier of 1 to 64 ASCII characters')

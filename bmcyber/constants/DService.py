"""Owned service identity and native host tools."""
from typing import Final
from enum import StrEnum


class DService:
    UNIT: Final[str] = 'bmcyber.service'
    SYSTEMCTL: Final[str] = 'systemctl'
    FAIL2BAN_CLIENT: Final[str] = 'fail2ban-client'
    FAIL2BAN_SERVER: Final[str] = 'fail2ban-server'
    GROUPADD: Final[str] = 'groupadd'


class ServiceAction(StrEnum):
    START = 'start'
    STOP = 'stop'
    RESTART = 'restart'


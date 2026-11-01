"""Owned service identity and native host tools."""
from typing import Final
from enum import StrEnum


class DService:
    UNIT: Final[str] = 'bmcyber.service'
    SYSTEMCTL: Final[str] = 'systemctl'
    GROUPADD: Final[str] = 'groupadd'


class ServiceAction(StrEnum):
    START = 'start'
    STOP = 'stop'
    RESTART = 'restart'


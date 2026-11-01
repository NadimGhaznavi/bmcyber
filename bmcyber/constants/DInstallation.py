"""Application-owned deployment layout and Python runtime requirements."""
from typing import Final
from enum import StrEnum


class DInstallation:
    PROJECT_NAME: Final[str] = 'BMCyber'
    DEPLOYMENT_READY: Final[bool] = True
    COPY_TREES: Final[tuple[str, ...]] = ('bmcyber', 'scripts', 'systemd', 'fail2ban')
    REQUIREMENTS_FILE: Final[str] = 'requirements.txt'
    COPY_FILES: Final[tuple[str, ...]] = (REQUIREMENTS_FILE,)
    MANIFEST: Final[str] = '.installation-manifest.json'
    VERSION_MARKER: Final[str] = '.deployment-version'
    SERVICE_OWNERSHIP: Final[str] = '.service-resources.json'
    PROJECT: Final[str] = 'project'
    FILES: Final[str] = 'files'
    VENV_OWNED: Final[str] = 'venv_owned'
    REMOVED: Final[str] = 'removed'
    CLIENT_LAUNCHER: Final[str] = 'scripts/bmcyber-client'
    SERVICE_RESOURCES: Final[tuple[tuple[str, str], ...]] = (
        ('systemd/bmcyber.service', 'etc/systemd/system/bmcyber.service'),
        ('fail2ban/action.d/bmcyber.conf', 'etc/fail2ban/action.d/bmcyber.conf'),
        ('fail2ban/filter.d/bmcyber-mycount.conf', 'etc/fail2ban/filter.d/bmcyber-mycount.conf'),
        ('fail2ban/jail.d/bmcyber-mycount.local', 'etc/fail2ban/jail.d/bmcyber-mycount.local'),
    )
    VENV_DIR: Final[str] = '.venv'
    SYSTEM_PYTHON: Final[str] = '/usr/bin/python3'
    RUNTIME_IMPORTS: Final[tuple[str, ...]] = ('zmq', 'bmcyber.__main__', 'bmcyber.client', 'bmcyber.services')
    COMMAND_TIMEOUT: Final[int] = 30
    VENV_TIMEOUT: Final[int] = 120
    PIP_TIMEOUT: Final[int] = 300


class InstallationAction(StrEnum):
    INSTALL = 'install'
    UPGRADE = 'upgrade'
    UNINSTALL = 'uninstall'


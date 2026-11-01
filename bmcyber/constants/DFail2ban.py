"""Native Fail2ban tools and the agreed MyCount journal contract."""
from typing import Final


class DFail2ban:
    CLIENT: Final[str] = 'fail2ban-client'
    SERVER: Final[str] = 'fail2ban-server'
    UNIT: Final[str] = 'fail2ban.service'
    MYCOUNT_UNIT: Final[str] = 'mycount-server.service'
    FILTER: Final[str] = 'bmcyber-mycount'
    FLOOD: Final[str] = 'bmcyber-mycount-flood'
    MALFORMED: Final[str] = 'bmcyber-mycount-malformed'
    JAILS: Final[tuple[str, ...]] = (FLOOD, MALFORMED)
    RULES: Final[tuple[tuple[str, str, int], ...]] = (
        (FLOOD, 'collection_request', 60),
        (MALFORMED, 'malformed_payload', 5),
    )
    FINDTIME: Final[int] = 60
    BANTIME: Final[int] = 72000
    JAIL_SOURCE: Final[str] = 'fail2ban/jail.d/bmcyber-mycount.local'
    RETAINED_JAIL: Final[str] = 'conf/mycount-jails.local'
    INACTIVE: Final[int] = 3


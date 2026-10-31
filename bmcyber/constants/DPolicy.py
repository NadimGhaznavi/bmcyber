"""Ban policy and nftables identifiers."""
from typing import Final


class DPolicy:
    BASE_HOURS: Final[int] = 20
    RANDOM_EXTRA_HOURS: Final[int] = 4
    SECONDS_PER_HOUR: Final[int] = 3600
    MAX_SECONDS: Final[int] = 604800
    COMMAND_TIMEOUT: Final[int] = 5
    NFT_EXECUTABLE: Final[str] = '/usr/sbin/nft'
    TABLE: Final[str] = 'bmcyber'
    TABLE_COMMENT: Final[str] = 'BMCyber timed IP bans'
    FAMILY: Final[str] = 'inet'
    SET_V4: Final[str] = 'banned_v4'
    SET_V6: Final[str] = 'banned_v6'
    CHAIN: Final[str] = 'input'
    PRIORITY: Final[int] = -10
    PROTECTED: Final[tuple[str, ...]] = ('127.0.0.0/8', '::1/128')
    SOURCE_PATTERN: Final[str] = r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}'

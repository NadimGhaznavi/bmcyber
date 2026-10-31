from typing import Final


class DBMCyber:
    VERSION: Final[str] = "0.1.0"
    CMDB_TYPE: Final[str] = "application"
    CMDB_SUBTYPE: Final[str] = "Application"
    CMDB_SUPPLIER: Final[str] = "Nadim-Daniel"
    CMDB_CODENAME: Final[str] = "Nobelium"
    CMDB_COMPONENTS = (("Configuration", "conf"),)
    CMDB_DATABASES = ()
    # Declare every owned listener; runtime defaults must use these bindings.
    CMDB_NETWORK: Final[tuple[tuple[str, str, int], ...]] = ()
    BASE_DIR: Final[str] = "/opt/prod/bmcyber"
    CONFIG_FILE: Final[str] = "conf/bmcyber.json"

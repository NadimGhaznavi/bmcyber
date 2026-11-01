from enum import StrEnum


class DText(StrEnum):
    CLIENT_DESCRIPTION = 'cli.client.description'
    SERVICE_DESCRIPTION = 'cli.service.description'
    FAILURE = 'cli.failure'
    SUCCESS = 'cli.success'
    CHECKED = 'cli.checked'
    INSTALL_DESCRIPTION = 'cli.install.description'
    INSTALL_CHECK_HELP = 'cli.install.check_help'
    INSTALL_ROOT_REQUIRED = 'cli.install.root_required'
    INSTALL_CHECKED = 'cli.install.checked'
    INSTALL_COMPLETE = 'cli.install.complete'
    INSTALL_REMOVED = 'cli.install.removed'
    SERVICES_DESCRIPTION = 'cli.services.description'

from enum import StrEnum


class DText(StrEnum):
    CLIENT_DESCRIPTION = 'cli.client.description'
    SERVICE_DESCRIPTION = 'cli.service.description'
    FAILURE = 'cli.failure'
    SUCCESS = 'cli.success'
    CHECKED = 'cli.checked'

"""CLI boundary for the owned service's explicit start/stop sequence."""
import argparse
import subprocess
import sys

from bmcyber.constants.DText import DText
from bmcyber.constants.DService import ServiceAction
from bmcyber.interface.CommandText import command_text
from bmcyber.interface.Configuration import Configuration
from bmcyber.interface.ServiceControl import ServiceControl


def main(argv=None):
    localizer, preference = command_text()
    parser = argparse.ArgumentParser(description=localizer.text(DText.SERVICES_DESCRIPTION))
    parser.add_argument('action', choices=list(ServiceAction))
    parser.add_argument('--locale', default=preference)
    args = parser.parse_args(argv)
    language = localizer.select(explicit=args.locale)
    control = ServiceControl()
    try:
        if args.action in (ServiceAction.START, ServiceAction.RESTART):
            Configuration.load()
            control.jails.check()
        if args.action in (ServiceAction.STOP, ServiceAction.RESTART):
            control.stop()
        if args.action in (ServiceAction.START, ServiceAction.RESTART):
            control.start()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(localizer.text(DText.FAILURE, locale=language,
                             detail=f'{error} {getattr(error, "stderr", "")}'), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

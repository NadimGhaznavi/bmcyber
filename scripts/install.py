#!/usr/bin/env python3
"""CLI boundary for BMCyber's application-owned installation interface."""
import argparse
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bmcyber.constants.DText import DText
from bmcyber.constants.DInstallation import InstallationAction
from bmcyber.interface.CommandText import command_text
from bmcyber.interface.Installation import Installation
from bmcyber.interface.Nftables import NftablesError


def main(argv=None):
    localizer, preference = command_text()
    language = localizer.select(explicit=preference)
    parser = argparse.ArgumentParser(description=localizer.text(DText.INSTALL_DESCRIPTION, locale=language))
    parser.add_argument('action', choices=list(InstallationAction))
    parser.add_argument('--check', action='store_true', help=localizer.text(DText.INSTALL_CHECK_HELP, locale=language))
    parser.add_argument('--locale', default=preference)
    args = parser.parse_args(argv)
    language = localizer.select(explicit=args.locale)
    if not args.check and os.geteuid() != 0:
        parser.error(localizer.text(DText.INSTALL_ROOT_REQUIRED, locale=language))
    try:
        installation = Installation(Path(__file__).resolve().parents[1])
        installation.apply(args.action, check=args.check)
    except (OSError, ValueError, TypeError, SyntaxError, NftablesError, subprocess.SubprocessError) as error:
        parser.exit(1, localizer.text(DText.FAILURE, locale=language,
                                    detail=f'{error} {getattr(error, "stderr", "")}') + '\n')
    if args.check:
        message = localizer.text(DText.INSTALL_CHECKED, locale=language,
                                 action=args.action, destination=str(installation.destination))
    elif args.action == InstallationAction.UNINSTALL:
        message = localizer.text(DText.INSTALL_REMOVED, locale=language,
                                 destination=str(installation.destination))
    else:
        message = localizer.text(DText.INSTALL_COMPLETE, locale=language, action=args.action,
                                 version=installation.metadata['VERSION'], destination=str(installation.destination))
    print(message)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

"""Thin Fail2ban action client: no detection, policy or firewall calls."""
import argparse
import sys

import zmq

from bmcyber.constants.DText import DText
from bmcyber.constants.DZMQ import DZMQ, Method
from bmcyber.entity.BanRequest import BanRequest
from bmcyber.interface.Configuration import Configuration
from bmcyber.interface.CommandText import command_text
from bmcyber.zmq.Client import Client

BMFORGE_COMPONENT = {'id': 'bmforge.fail2ban', 'spec_version': '0.3.0'}


def main(argv=None):
    localizer, preference = command_text()
    parser = argparse.ArgumentParser(description=localizer.text(DText.CLIENT_DESCRIPTION))
    parser.add_argument('--config')
    parser.add_argument('--locale', default=preference)
    parser.add_argument('--timeout', type=float)
    commands = parser.add_subparsers(dest='method', required=True)
    ban = commands.add_parser(Method.BAN)
    ban.add_argument('--ip', required=True)
    ban.add_argument('--source', required=True)
    commands.add_parser(Method.HEALTH)
    args = parser.parse_args(argv)
    language = localizer.select(explicit=args.locale)
    try:
        configuration = Configuration.load(args.config, timeout_seconds=args.timeout)
        payload = {}
        if args.method == Method.BAN:
            request = BanRequest(args.ip, args.source)
            payload = {DZMQ.IP: request.ip, DZMQ.SOURCE: request.source}
        result = Client(configuration).request(args.method, payload)
    except (OSError, ValueError, zmq.ZMQError) as error:
        print(localizer.text(DText.FAILURE, locale=language, detail=str(error)), file=sys.stderr)
        return 1
    print(localizer.text(DText.SUCCESS, locale=language, method=args.method, result=result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

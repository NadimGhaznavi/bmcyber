"""Root service lifecycle; IPC provision and exclusivity precede binding."""
import argparse
import logging
import os
from pathlib import Path
import signal
import subprocess
from threading import Event

import zmq

from bmcyber.activity.BlockAddress import BlockAddress
from bmcyber.constants.DText import DText
from bmcyber.constants.DZMQ import DZMQ
from bmcyber.interface.Configuration import Configuration
from bmcyber.interface.IPCEndpoint import IPCEndpoint
from bmcyber.interface.Localizer import Localizer
from bmcyber.interface.Nftables import Nftables, NftablesError
from bmcyber.interface.RequestHandler import RequestHandler
from bmcyber.zmq.Server import Server


def main(argv=None):
    localizer = Localizer(Path(__file__).parent / 'locales')
    parser = argparse.ArgumentParser(description=localizer.text(DText.SERVICE_DESCRIPTION))
    parser.add_argument('--config')
    parser.add_argument('--check-config', action='store_true')
    parser.add_argument('--locale', default='en')
    args = parser.parse_args(argv)
    language = localizer.select(explicit=args.locale)
    logging.basicConfig(level=logging.INFO)
    try:
        configuration = Configuration.load(args.config)
        if args.check_config:
            print(localizer.text(DText.CHECKED, locale=language))
            return 0
        if os.geteuid() != 0:
            raise ValueError('the BMCyber service must run as root')
        stopped = Event()
        for name in (signal.SIGTERM, signal.SIGINT):
            signal.signal(name, lambda *_: stopped.set())
        firewall = Nftables()
        # Umask belongs to the process lifecycle, never the socket worker.
        os.umask(DZMQ.SERVICE_UMASK)
        with IPCEndpoint(configuration.socket_path) as endpoint:
            firewall.initialize()
            handler = RequestHandler(BlockAddress(configuration, firewall), firewall)
            with Server(configuration.endpoint, handler, bound=endpoint.bound,
                        timeout_seconds=configuration.timeout_seconds) as server:
                logging.info('BMCyber ready at %s', configuration.endpoint)
                while not stopped.wait(DZMQ.POLL_MS / 1000):
                    server.check()
    except (OSError, ValueError, NftablesError, subprocess.SubprocessError, zmq.ZMQError) as error:
        logging.error('%s', localizer.text(DText.FAILURE, locale=language, detail=str(error) + str(getattr(error, "stderr", ""))))
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

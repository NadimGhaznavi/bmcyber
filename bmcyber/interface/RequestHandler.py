"""Application dispatch for the declared ban and health messages."""
import logging
import subprocess

from bmcyber.constants.DZMQ import DZMQ, ErrorCode, Method
from bmcyber.entity.BanRequest import BanRequest
from bmcyber.interface.Nftables import NftablesError
from bmcyber.zmq.Server import error_payload


class RequestHandler:
    def __init__(self, blocking, firewall):
        self.blocking = blocking
        self.firewall = firewall

    def __call__(self, message):
        if message.target not in (None, DZMQ.SERVICE):
            return error_payload(ErrorCode.WRONG_TARGET, 'Incorrect target.')
        try:
            if message.method == Method.HEALTH:
                if message.payload:
                    raise ValueError('health requires an empty payload')
                self.firewall.inspect()
                return {DZMQ.STATUS: DZMQ.OK}
            if message.method != Method.BAN:
                return error_payload(ErrorCode.UNKNOWN_METHOD, 'Unsupported method.')
            if set(message.payload) != {DZMQ.IP, DZMQ.SOURCE}:
                raise ValueError('ban requires only ip and source')
            request = BanRequest(message.payload[DZMQ.IP], message.payload[DZMQ.SOURCE])
            duration = self.blocking.execute(request)
            logging.info('ban ip=%s source=%s selected_duration_seconds=%s', request.ip, request.source, duration)
            return {DZMQ.STATUS: DZMQ.OK, DZMQ.IP: request.ip, DZMQ.DURATION: duration}
        except ValueError as error:
            return error_payload(ErrorCode.INVALID_REQUEST, str(error))
        except (OSError, subprocess.SubprocessError, NftablesError) as error:
            logging.error('nftables operation failed: %s %s', error, getattr(error, 'stderr', ''))
            return error_payload(ErrorCode.ENFORCEMENT_FAILED, 'nftables operation failed or has an uncertain outcome.')

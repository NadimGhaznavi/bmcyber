"""Socket-owning REQ/REP worker, adapted from the pinned BMForge snapshot."""
from collections.abc import Callable
from threading import Event, Thread

import zmq

from bmcyber.constants.DZMQ import DZMQ, ErrorCode
from bmcyber.zmq.Message import Message

BMFORGE_COMPONENT = {'id': 'bmforge.zmq-server', 'spec_version': '0.4.0'}


def error_payload(code, message):
    return {DZMQ.STATUS: DZMQ.ERROR, DZMQ.ERROR: {DZMQ.CODE: code, DZMQ.MESSAGE: message}}


class Server:
    def __init__(self, endpoint: str, handler: Callable, *, bound: Callable = lambda: None,
                 timeout_seconds=DZMQ.TIMEOUT_SECONDS):
        self.endpoint = endpoint
        self.handler = handler
        self.bound = bound
        self.timeout_ms = int(timeout_seconds * 1000)
        self.ready = Event()
        self.stop = Event()
        self.error = None
        self.thread = Thread(target=self._serve, name=DZMQ.SERVICE, daemon=True)

    def __enter__(self):
        self.thread.start()
        self.ready.wait()
        self.check()
        return self

    def __exit__(self, *_):
        self.stop.set()
        self.thread.join()
        self.check()

    def check(self):
        if self.error is not None:
            raise self.error

    def _serve(self):
        try:
            with zmq.Context() as context:
                with context.socket(zmq.REP) as socket:
                    socket.setsockopt(zmq.LINGER, 0)
                    socket.setsockopt(zmq.SNDTIMEO, self.timeout_ms)
                    socket.setsockopt(zmq.MAXMSGSIZE, DZMQ.MAX_MESSAGE_BYTES)
                    socket.bind(self.endpoint)
                    self.bound()
                    self.ready.set()
                    while not self.stop.is_set():
                        if not socket.poll(DZMQ.POLL_MS):
                            continue
                        request = None
                        try:
                            frames = socket.recv_multipart()
                            if len(frames) != 1:
                                raise ValueError('one frame required')
                            request = Message.from_json(frames[0])
                        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
                            payload = error_payload(ErrorCode.INVALID_REQUEST, 'Invalid request envelope.')
                        else:
                            try:
                                payload = self.handler(request)
                            except Exception:
                                payload = error_payload(ErrorCode.INTERNAL_ERROR, 'Application handler failed.')
                        reply = Message(DZMQ.SERVICE, request.method if request else DZMQ.ERROR,
                                        target=request.sender if request else None, payload=payload)
                        socket.send(reply.to_json())
        except BaseException as error:
            self.error = error
        finally:
            self.ready.set()

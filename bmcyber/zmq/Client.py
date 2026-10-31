"""One bounded exchange per invocation; no retries after uncertain replies."""
import zmq

from bmcyber.constants.DZMQ import DZMQ
from bmcyber.zmq.Message import Message


class Client:
    def __init__(self, configuration):
        self.configuration = configuration

    def request(self, method, payload, *, sender='bmcyber-client'):
        request = Message(sender, method, target=DZMQ.SERVICE, payload=payload)
        with zmq.Context() as context:
            with context.socket(zmq.REQ) as socket:
                socket.setsockopt(zmq.LINGER, 0)
                socket.setsockopt(zmq.IMMEDIATE, 1)
                socket.setsockopt(zmq.SNDTIMEO, int(self.configuration.timeout_seconds * 1000))
                socket.setsockopt(zmq.RCVTIMEO, int(self.configuration.timeout_seconds * 1000))
                socket.setsockopt(zmq.MAXMSGSIZE, DZMQ.MAX_MESSAGE_BYTES)
                socket.connect(self.configuration.endpoint)
                socket.send(request.to_json())
                reply = Message.from_json(socket.recv())
        if reply.sender != DZMQ.SERVICE or reply.target != sender or reply.method != method:
            raise ValueError('uncorrelated service acknowledgement')
        if reply.payload.get(DZMQ.STATUS) != DZMQ.OK:
            raise ValueError(str(reply.payload.get(DZMQ.ERROR, 'missing acknowledgement')))
        return reply.payload

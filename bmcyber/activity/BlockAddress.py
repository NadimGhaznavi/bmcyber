"""Choose the duration and request enforcement; keep no ban state."""
import ipaddress
from random import SystemRandom

from bmcyber.constants.DPolicy import DPolicy


class BlockAddress:
    def __init__(self, configuration, firewall, *, random=None):
        self.configuration = configuration
        self.firewall = firewall
        self.random = random or SystemRandom()
        self.protected = tuple(ipaddress.ip_network(item) for item in configuration.protected_ips)

    def execute(self, request):
        address = ipaddress.ip_address(request.ip)
        if any(address.version == network.version and address in network for network in self.protected):
            raise ValueError('the requested IP is protected by service policy')
        seconds = round(self.configuration.base_hours * DPolicy.SECONDS_PER_HOUR)
        extra = int(self.configuration.random_extra_hours * DPolicy.SECONDS_PER_HOUR)
        duration = seconds + self.random.randint(0, extra)
        self.firewall.apply(request.ip, duration)
        return duration

"""The application's one owned nftables table; no policy or saved state."""
import ipaddress
import json
import subprocess

from bmcyber.constants.DPolicy import DPolicy

BMFORGE_COMPONENT = {'id': 'bmforge.nftables', 'spec_version': '0.2.0'}


class NftablesError(RuntimeError):
    """The owned enforcement structure is unavailable or invalid."""



class Nftables:
    def __init__(self, *, executable=DPolicy.NFT_EXECUTABLE, run=subprocess.run):
        self.executable = executable
        self.run = run

    def command(self, *arguments, script=None):
        result = self.run([self.executable, *arguments], input=script, text=True,
                          capture_output=True, timeout=DPolicy.COMMAND_TIMEOUT, check=True)
        return json.loads(result.stdout) if '-j' in arguments else result.stdout

    @staticmethod
    def rules():
        return f'''create table inet {DPolicy.TABLE} {{ comment "{DPolicy.TABLE_COMMENT}"; }}
add set inet {DPolicy.TABLE} {DPolicy.SET_V4} {{ type ipv4_addr; flags timeout; }}
add set inet {DPolicy.TABLE} {DPolicy.SET_V6} {{ type ipv6_addr; flags timeout; }}
add chain inet {DPolicy.TABLE} {DPolicy.CHAIN} {{ type filter hook input priority {DPolicy.PRIORITY}; policy accept; }}
add rule inet {DPolicy.TABLE} {DPolicy.CHAIN} ip saddr @{DPolicy.SET_V4} drop
add rule inet {DPolicy.TABLE} {DPolicy.CHAIN} ip6 saddr @{DPolicy.SET_V6} drop
'''

    def exists(self):
        # Discover table identifiers only; never read another table's rules.
        data = self.command('-j', 'list', 'tables')
        return any(item.get('table', {}).get('family') == DPolicy.FAMILY
                   and item.get('table', {}).get('name') == DPolicy.TABLE for item in data['nftables'])

    def initialize(self, *, check=False):
        if self.exists():
            self.inspect()
        else:
            self.command(*(['--check'] if check else []), '-f', '-', script=self.rules())
            if not check:
                self.inspect()

    def inspect(self):
        data = self.command('-j', 'list', 'table', DPolicy.FAMILY, DPolicy.TABLE)
        objects = data['nftables']
        tables = [item['table'] for item in objects if 'table' in item]
        chains = [item['chain'] for item in objects if 'chain' in item]
        sets = [item['set'] for item in objects if 'set' in item]
        rules = [item['rule'] for item in objects if 'rule' in item]
        if (len(tables) != 1 or tables[0].get('comment') != DPolicy.TABLE_COMMENT
                or len(chains) != 1 or len(sets) != 2 or len(rules) != 2
                or any(set(item) - {'metainfo', 'table', 'chain', 'set', 'rule'} for item in objects)):
            raise NftablesError('unexpected structure in the BMCyber nftables table')
        chain = chains[0]
        expected = {'name': DPolicy.CHAIN, 'type': 'filter', 'hook': 'input',
                    'prio': DPolicy.PRIORITY, 'policy': 'accept'}
        if any(chain.get(key) != value for key, value in expected.items()):
            raise NftablesError('unexpected BMCyber input chain')
        expected_sets = {DPolicy.SET_V4: 'ipv4_addr', DPolicy.SET_V6: 'ipv6_addr'}
        if {item.get('name') for item in sets} != set(expected_sets):
            raise NftablesError('unexpected BMCyber address sets')
        for item in sets:
            if item.get('type') != expected_sets[item['name']] or item.get('flags') != ['timeout']:
                raise NftablesError('BMCyber sets require the correct address family and timeout support')
        expressions = []
        for protocol, name in (('ip', DPolicy.SET_V4), ('ip6', DPolicy.SET_V6)):
            expressions.append([{'match': {'op': '==', 'left': {'payload': {'protocol': protocol, 'field': 'saddr'}},
                                           'right': '@' + name}}, {'drop': None}])
        if any(rule.get('chain') != DPolicy.CHAIN for rule in rules) or [rule.get('expr') for rule in rules] != expressions:
            raise NftablesError('unexpected BMCyber drop rules')
        return data

    @staticmethod
    def address(value):
        if not isinstance(value, str) or '%' in value:
            raise ValueError('expected a numeric address without a zone')
        address = ipaddress.ip_address(value)
        return str(address), DPolicy.SET_V4 if address.version == 4 else DPolicy.SET_V6

    def apply(self, value, duration):
        address, name = self.address(value)
        if type(duration) is not int or not 1 <= duration <= DPolicy.MAX_SECONDS:
            raise ValueError('duration must be a positive integer within the declared limit')
        self.inspect()
        # Native add is intentionally used: no deadline map and no hidden retry.
        self.command('-f', '-', script=f'add element inet {DPolicy.TABLE} {name} {{ {address} timeout {duration}s }}\n')

    def remove(self, value):
        address, name = self.address(value)
        data = self.inspect()
        target = next(item['set'] for item in data['nftables'] if item.get('set', {}).get('name') == name)
        elements = target.get('elem', [])
        def element_value(item):
            if isinstance(item, str):
                return item
            return item.get('elem', {}).get('val')
        if any(element_value(item) == address for item in elements):
            self.command('-f', '-', script=f'delete element inet {DPolicy.TABLE} {name} {{ {address} }}\n')

    def uninstall(self):
        if self.exists():
            self.inspect()
            self.command('delete', 'table', DPolicy.FAMILY, DPolicy.TABLE)

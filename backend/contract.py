import ipaddress
from core import FEATURES

def classify(prefix, origin, registry):
    network = ipaddress.ip_network(prefix, strict=True)
    candidates = [(ipaddress.ip_network(p), owners) for p, owners in registry.items() if network.version == ipaddress.ip_network(p).version and network.subnet_of(ipaddress.ip_network(p))]
    if not candidates:
        return 'unknown'
    _, owners = max(candidates, key=lambda entry: entry[0].prefixlen)
    return 'normal' if origin in owners else 'suspicious'

def compatible(features):
    return features == FEATURES



import ipaddress
from hypothesis.strategies import ip_addresses, one_of, integers, lists
from hypothesis import given, assume

from twisted.internet.endpoints import TCP4ServerEndpoint, TCP6ServerEndpoint

from fowl.policy import LocalhostAnyPortsListenPolicy, LocalhostTcpPortsListenPolicy


def ip_address_to_listener(reactor, port, ipaddr):
    """
    Convert an ipaddress.IPv4Address or IPv6Address to an
    TCP4ServerEndpoint (or TCP6ServerEndpoint)
    """
    if isinstance(ipaddr, ipaddress.IPv4Address):
        return TCP4ServerEndpoint(reactor, port, interface=str(ipaddr))
    elif isinstance(ipaddr, ipaddress.IPv6Address):
        return TCP6ServerEndpoint(reactor, port, interface=str(ipaddr))
    raise ValueError(f"Unknown ipaddress: {ipaddr}")


@given(
    integers(1, 65536),  # any port we might care about
    one_of(
        ip_addresses(network="127.0.0.0/8"),
        ip_addresses(network="::1"),
        # these are "link-local" but I believe different meaning from "localhost"?
        # ip_addresses(network="fe80::/64"),
        # also what about "ipv4-mapped addresses that are actually localhost? possible? worth it?
    )
)
def test_policy_any_acceptable(reactor, port, ipaddr):
    """
    LocalhostAnyPortsPolicy allows all valid localhost style addresses
    we might like
    """
    endpoint = ip_address_to_listener(reactor, port, ipaddr)
    policy = LocalhostAnyPortsListenPolicy()
    assert policy.can_listen(endpoint) == True, "Listen on a localhost port"


@given(
    integers(1, 65536),  # any port we might care about
    ip_addresses(),
)
def test_policy_any_bad(reactor, port, ipaddr):
    """
    LocalhostAnyPortsPolicy disallows all IP addresses that are NOT
    localhost
    """
    assume(not ipaddress.ip_address(ipaddr).is_loopback)
    endpoint = ip_address_to_listener(reactor, port, ipaddr)
    policy = LocalhostAnyPortsListenPolicy()
    assert policy.can_listen(endpoint) == False, "Should only allow loopback addresses"


@given(
    integers(1, 65536),  # any port we might care about
    lists(integers(1, 65536)),  # allowed ports in our policy
    ip_addresses(),
)
def test_policy_specific_ports(reactor, port, allowed_ports, ipaddr):
    """
    LocalhostAnyPortsPolicy disallows all IP addresses that are NOT
    localhost
    """
    is_local = ipaddress.ip_address(ipaddr).is_loopback
    is_allowed = port in allowed_ports
    endpoint = ip_address_to_listener(reactor, port, ipaddr)
    expected_result = True if is_local and is_allowed else False

    policy = LocalhostTcpPortsListenPolicy(allowed_ports)
    assert policy.can_listen(endpoint) == expected_result, f"what port={endpoint._port} if={endpoint._interface} {expected_result} {port} {allowed_ports} {ipaddr} {policy.can_listen(endpoint)}"

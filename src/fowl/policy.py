
import ipaddress

from attr import frozen
from zope.interface import Interface, implementer
from twisted.internet.endpoints import (
    TCP4ServerEndpoint,
    TCP6ServerEndpoint,
    TCP4ClientEndpoint,
    TCP6ClientEndpoint,
)


class IClientListenPolicy(Interface):
    """
    A way to ask which endpoints are acceptable to listen upon for a client.
    """

    def can_listen(self, endpoint) -> bool:
        """
        :returns: True if the given IStreamServerEndpoint is acceptable to
            this policy
        """


class IClientConnectPolicy(Interface):
    """
    Ask what endpoints are acceptable to connect on
    """

    def can_connect(self, endpoint) -> bool:
        """
        :returns: True if the given IStreamClientEndpoint is acceptable to
            this policy
        """


# XXX if i'm offline, "localhost" doesn't work (with ip_address()) -- when _does_ it work, and why?
# XXX with radios off entirely, i'm seeing "" (empty string) as the addr here
def is_localhost(addr: str) -> bool:
    if addr.strip() == "":
        return False
    if addr == "localhost":
        return True
    ip = ipaddress.ip_address(addr)
    return ip.is_loopback


@implementer(IClientListenPolicy)
class LocalhostAnyPortsListenPolicy:
    """
    Accepts any port as long as the interface is a local one (i.e. ::1
    or localhost or 127.0.0.1/8) according to the "ipaddress" library.
    """
    def can_listen(self, endpoint) -> bool:
        if isinstance(endpoint, (TCP6ServerEndpoint, TCP4ServerEndpoint)):
            return is_localhost(endpoint._interface)
        return False


@implementer(IClientListenPolicy)
@frozen
class LocalhostTcpPortsListenPolicy(LocalhostAnyPortsListenPolicy):
    # which ports we will accept
    ports: list[int]

    def can_listen(self, endpoint) -> bool:
        if super().can_listen(endpoint):
            # if we're here, parent has checked types too
            if endpoint._port in self.ports:
                return True
        return False


@implementer(IClientListenPolicy)
class AnyListenPolicy:
    """
    Accepts any listener at all. DANGER.
    """
    def can_listen(self, endpoint) -> bool:
        return True


@implementer(IClientConnectPolicy)
class LocalhostAnyPortsConnectPolicy:
    """
    Accepts any port as long as the interface is a local one (i.e. ::1
    or localhost or 127.0.0.1/8) according to the "ipaddress" library.
    """
    def can_connect(self, endpoint) -> bool:
        if isinstance(endpoint, (TCP6ClientEndpoint, TCP4ClientEndpoint)):
            return is_localhost(endpoint._host)
        return False


@implementer(IClientConnectPolicy)
class AnyConnectPolicy:
    """
    Accepts any connection at all. DANGER.
    """
    def can_connect(self, endpoint) -> bool:
        return True


@implementer(IClientConnectPolicy)
@frozen
class LocalhostTcpPortsConnectPolicy(LocalhostAnyPortsConnectPolicy):
    # which ports we will accept
    ports: list[int]

    def can_connect(self, endpoint) -> bool:
        if super().can_connect(endpoint):
            # if we're here, parent has checked types too
            if endpoint._port in self.ports:
                return True
        return False

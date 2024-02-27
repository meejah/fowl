
import ipaddress

from attr import frozen
from zope.interface import Interface, implementer
from twisted.internet.interfaces import IStreamServerEndpoint
from twisted.internet.endpoints import (
    TCP4ServerEndpoint,
    TCP6ServerEndpoint,
)


class IClientListenPolicy(Interface):
    """
    A way to ask endpoints are acceptable to listen upon for a client.
    """

    def can_listen(self, endpoint) -> bool:
        """
        :returns: True if the given IStreamServerEndpoint is acceptable to
            this policy
        """


def is_localhost(addr: str) -> bool:
    ip = ipaddress.ip_address(addr)
    return ip.is_loopback


@implementer(IClientListenPolicy)
class LocalhostAnyPortsPolicy:
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
class LocalhostTcpPortsPolicy(LocalhostAnyPortsPolicy):
    # which ports we will accept
    ports: list[int]

    def can_listen(self, endpoint) -> bool:
        if super().can_listen(endpoint):
            # if we're here, parent has checked types too
            if endpoint._port in self.ports:
                return True
        return False

from typing import Optional
from attrs import frozen


class FowlOutputMessage:
    """
    An information message from fowld to the controller
    """


class FowlCommandMessage:
    """
    A command from the controller to fowld
    """


# if we had ADT / Union types, these would both be that -- is this as
# close as we can get in Python?


@frozen
class Welcome(FowlOutputMessage):
    """
    We have connected to the Mailbox Server and received the
    Welcome message.
    """
    url: str  # server address
    # open-ended information from the server
    welcome: dict


@frozen
class WormholeClosed(FowlOutputMessage):
    """
    The wormhole has been terminated.
    """
    result: str


@frozen
class AllocateCode(FowlCommandMessage):
    """
    Create a fresh code on the server
    """
    length: Optional[int] = None


@frozen
class SetCode(FowlCommandMessage):
    """
    Give a code we know to the server
    """
    code: str


@frozen
class CodeAllocated(FowlOutputMessage):
    """
    The secret wormhole code has been determined
    """
    code: str


@frozen
class PeerConnected(FowlOutputMessage):
    """
    We have evidence that the peer has connected
    """
    # hex-encoded 32-byte hash output (should match other peer)
    verifier: str
    versions: dict


@frozen
class GrantPermission(FowlCommandMessage):
    """
    Grant additional listen or connection privileges. Both are lists
    of valid ports between 1 and 65535 inclusive.
    """
    listen: list[int]
    connect: list[int]


@frozen
class DangerDisablePermissionCheck(FowlCommandMessage):
    """
    DANGER: allow listening or connecting to anything. Can be
    dangerous, you must know the implications.
    """


@frozen
class LocalListener(FowlCommandMessage):
    """
    We wish to open a local listener.
    """
    listen: str  # Twisted server-type endpoint string
    connect: str  # Twisted client-type endpoint string


@frozen
class RemoteListener(FowlCommandMessage):
    """
    We wish to open a listener on the peer.
    """
    listen: str  # Twisted server-type endpoint string
    connect: str  # Twisted client-type endpoint string


@frozen
class Listening(FowlOutputMessage):
    """
    We have opened a local listener.

    Any connections to this listener will result in a subchannel and a
    connect on the other side (to "connected_endpoint"). This message
    may result from a LocalListener or a RemoteListener command. This
    message will always appear on the side that's actually listening.
    """
    listen: str  # Twisted server-type endpoint string
    connect: str  # Twisted client-type endpoint string


@frozen
class RemoteListeningFailed(FowlOutputMessage):
    """
    We have failed to open a listener on the remote side.
    """
    listen: str  # Twisted server-type endpoint string
    reason: str


@frozen
class RemoteListeningSucceeded(FowlOutputMessage):
    """
    The remote peer suceeded at fulfilling our listen request.
    """
    listen: str  # Twisted server-type endpoint string


@frozen
class RemoteConnectFailed(FowlOutputMessage):
    """
    Our peer could not connect
    """
    id: int
    reason: str


@frozen
class OutgoingConnection(FowlOutputMessage):
    """
    Something has connected to one of our listeners (and we are making
    an outgoing subchannel to the other peer).
    """
    id: int
    endpoint: str  # connection to here on far side
    # XXX local_listener: str ??


@frozen
class OutgoingLost(FowlOutputMessage):
    """
    We have lost one of our connections
    """
    id: int
    reason: str


@frozen
class OutgoingDone(FowlOutputMessage):
    """
    We have lost one of our connections
    """
    id: int


@frozen
class IncomingConnection(FowlOutputMessage):
    """
    The other side is requesting we open a connection
    """
    id: int
    endpoint: str


@frozen
class IncomingLost(FowlOutputMessage):
    """
    We have lost one of our connections
    """
    id: int
    reason: str


@frozen
class IncomingDone(FowlOutputMessage):
    """
    An incoming connection has ended successfully
    """
    id: int


@frozen
class BytesIn(FowlOutputMessage):
    id: int
    bytes: int


@frozen
class BytesOut(FowlOutputMessage):
    id: int
    bytes: int


@frozen
class WormholeError(FowlOutputMessage):
    message: str


@frozen
class PleaseCloseWormhole(FowlOutputMessage):
    reason: str


#XXX these aren't really used; why state-machine has them?
@frozen
class SendMessageToPeer(FowlOutputMessage):
    message: str


@frozen
class GotMessageFromPeer(FowlOutputMessage):
    message: str

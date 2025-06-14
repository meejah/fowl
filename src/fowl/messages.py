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


class FowlInternalControl:
    "A message from the state-machine to outside, basically?"
    pass


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
    # XXX roost()
    name: str  # unique name for this service
    listen_port: Optional[int] = None  # port to listen locally (or select randomly)


@frozen
class RemoteListener(FowlCommandMessage):
    """
    We wish to open a listener on the peer.
    """
    # XXX fledge()
    name: str  # Unique name for this service
    listen_port: Optional[int] = None  # port to listen on (or let peer select)
    connect_port: Optional[int] = None  # port to connect here on


@frozen
class Ping(FowlCommandMessage):
    ping_id: int


@frozen
class Listening(FowlOutputMessage):
    """
    We have opened a local listener.

    Any connections to this listener will result in a subchannel and a
    connect on the other side. This message may result from a
    LocalListener or a RemoteListener command.

    This message will always appear on the side that's actually
    listening.
    """
    name: str  # unique name for this service
    listening_port: int


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
    name: str  # unique name for this service
    local_port: int  # where we connect locally


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
    service_name: str
    channel_id: str


@frozen
class OutgoingLost(FowlOutputMessage):
    """
    We have lost one of our connections
    """
    service_name: str
    reason: str


@frozen
class OutgoingDone(FowlOutputMessage):
    """
    We have lost one of our connections
    """
    service_name: str


@frozen
class IncomingConnection(FowlOutputMessage):
    """
    The other side is requesting we open a connection
    """
    service_name: str
    channel_id: str


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
class PleaseCloseWormhole(FowlInternalControl):
    reason: str


@frozen
class Pong(FowlOutputMessage):
    ping_id: int
    time_of_flight: float


#XXX these aren't really used; why state-machine has them?
@frozen
class SendMessageToPeer(FowlOutputMessage):
    message: str


@frozen
class GotMessageFromPeer(FowlOutputMessage):
    message: str

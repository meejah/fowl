import os
import socket
import struct
from attr import define
from typing import Optional, Any

import msgpack
from ipaddress import IPv4Address, IPv6Address
from twisted.internet.interfaces import IStreamClientEndpoint, IStreamServerEndpoint, IReactorSocket
from twisted.internet.endpoints import TCP4ServerEndpoint, TCP6ServerEndpoint
from twisted.internet.endpoints import TCP4ClientEndpoint, TCP6ClientEndpoint
from twisted.internet.endpoints import AdoptedStreamServerEndpoint
from twisted.internet.defer import ensureDeferred
from twisted.internet.protocol import Factory
from twisted.python.reflect import requireModule

from zope.interface import implementer

from wormhole._dilation.manager import DilatedWormhole
from wormhole.cli.public_relay import TRANSIT_RELAY

from .observer import When
from ._proto import FowlSubprotocolListener, FowlCommandsListener, _SendFowlCommand
from .status import _StatusTracker
from .tcp import allocate_tcp_port

# not available on Windows
fcntl = requireModule("fcntl")


def create_coop(reactor, wormhole, status_tracker=None):
    # it is "_FowlCoop.dilate()" that does the magic -- inject our
    # subprotocols etc
    if status_tracker is None:
        status_tracker = _StatusTracker()
    return _FowlCoop(reactor, wormhole, status_tracker)


@define
class FowlChannelDaemonHere:
    unique_name: str  # (must be UNIQUE across all of this Fowl session)
    endpoint: IStreamClientEndpoint  # how to connect to our daemon

    @property
    def listen_port(self):
        if isinstance(self.endpoint, TCP4ClientEndpoint):
            return self.endpoint._port
        elif isinstance(self.endpoint, TCP6ClientEndpoint):
            return self.endpoint._port
        raise ValueError(
            ".endpoint is neither TCP4 nor TCP6 server"
        )


@define
class FowlChannelDaemonThere:
    """
    Represents the state of a channel permitted by 'roost()' on this
    side (which will only exist after the other peer calls 'fledge()'
    on their side)
    """
    unique_name: str  # (must be UNIQUE across all of this Fowl session)
    endpoint: IStreamServerEndpoint  # where we're listening locally
    remote_connect_port: Optional[int] = None
    port: Any = None

    @property
    def connect_port(self) -> int:
        if self.port is not None:
            return self.port._realPortNumber
        elif isinstance(self.endpoint, TCP4ServerEndpoint):
            return self.endpoint._port
        elif isinstance(self.endpoint, TCP6ServerEndpoint):
            return self.endpoint._port
        raise ValueError(
            ".listener endpoint is neither TCP4 nor TCP6 server, and we have no port"
        )

    def _is_listening(self, port):
        """
        Internal helper. Called when we learn our port, after listening is
        complete locally.
        """
        self.port = port


@implementer(IStreamServerEndpoint)
class _LocalListeningEndpoint:
    """
    Listen on a local port.

    When `desired_port` is `None`, and on systems that support it
    (POSIX- adjacent), we ask the OS to choose an unused port and then
    adopt that filedescriptor. This has no 'race' opportunity.

    Otherwise, we choose a _currently_ unused port, and then listen on
    it (e.g. Windows). This (short, but non-zero) time interval allows
    the opportunity for the chosen port to become used before we get
    around to it; this will result in an error.

    If `desired_port` is set, we use that. It is an error if the port
    is already used by the time we try to listen.
    """
    def __init__(self, reactor, desired_port, bind=None):
        self._reactor = reactor
        self._desired_port = desired_port
        self._bind = bind

    def _set_desired_port(self, value):
        """
        Internal helper. If not already set, request a specific port.
        """
        value = int(value)
        if value < 1 or value > 65535:
            raise ValueError(
                f"Port {value} is out of range"
            )
        if self._desired_port is None:
            self._desired_port = value
        else:
            if self._desired_port != value:
                raise RuntimeError(
                    f"Desired port {value} does not match {self._desired_port}"
                )

    async def listen(self, factory):
        endpoint = None
        if self._desired_port is None and \
           fcntl is not None and \
           IReactorSocket.providedBy(self._reactor):
                # On POSIX we can take this very safe approach of binding the
                # actual socket to an address.  Once the bind succeeds here, we're
                # no longer subject to any future EADDRINUSE problems.
                s = socket.socket()
                try:
                    s.bind(('' if self._bind is None else self._bind, 0))
                    portnum = s.getsockname()[1]
                    s.listen(1)
                    # File descriptors are a relatively scarce resource.  The
                    # cleanup process for the file descriptor we're about to dup
                    # is unfortunately complicated.  In particular, it involves
                    # the Python garbage collector.  See CleanupEndpoint for
                    # details of that.  Here, we need to make sure the garbage
                    # collector actually runs frequently enough to make a
                    # difference.  Normally, the garbage collector is triggered by
                    # allocations.  It doesn't know about *file descriptor*
                    # allocation though.  So ... we'll "teach" it about those,
                    # here.
                    fd = os.dup(s.fileno())
                    flags = fcntl.fcntl(fd, fcntl.F_GETFD)
                    flags = flags | os.O_NONBLOCK | fcntl.FD_CLOEXEC
                    fcntl.fcntl(fd, fcntl.F_SETFD, flags)
                    endpoint = CleanupEndpoint(
                        AdoptedStreamServerEndpoint(self._reactor, fd, socket.AF_INET),
                        fd,
                    )
                finally:
                    s.close()

        if endpoint is None:
            portnum = self._desired_port
            if portnum is None:
                # Get a random port number and fall through.  This is
                # necessary on Windows where Twisted doesn't offer
                # IReactorSocket.  This approach is error prone as it
                # is inherently a race: between when we set "portnum"
                # and when we call ".listen()", something else
                # (e.g. another process) could use this port.
                portnum = allocate_tcp_port()
            endpoint = TCP4ServerEndpoint(
                self._reactor,
                portnum,
                interface="localhost" if self._bind is None else self._bind,
            )
        port = await endpoint.listen(factory)
        return port


class _FowlCoop:
    """
    Chickens live in coops.

    Set up mappings for Fowl endpoints on either peer.

    This acts somewhat like the 'Builder' pattern: you arrange for
    local or remote forwarding, and then sometime after the `dilate()`
    call, those things happen.

    You can also add configuration after the `dilate()` call.

    Fowl is built around the assumption that we are doing classic
    "server / client" networking -- but between two peers. The
    important thing that calling code needs to decide is "which peer
    runs the server" (and thus the other peer runs a client).

    Sometimes this is obvious: for a use-case like screen-sharing, the
    peer who has a screen to share is "the host". For Git repository
    sharing, the peer with the bare repository is "the host". In such
    cases, it's likely you'll want to run the daemon-side software on
    "the host" -- following this pattern allows multiple
    "client"-style peers to connect (e.g. multiple peers watching the
    shared screen, or cloning the hosted Git repository).

    The API methods `fledge()` and `roost()` are a pair. They both
    take a "unique_name" argument, and for any particular
    `unique_name`, the peer that calls `fledge(name)` runs the server
    / deamon style networking while the peer that calls `roost(name)`
    runs the client style networking.

    Technically speaking, what is happening here is that the "real"
    application -provided daemon/server software listens on the peer
    that calls `fledge("foo")`. Calling this method causes Fowl to
    send a _request_ to the other peer to forward the service named
    "foo"; if that peer has called `roost("foo")` -- giving permission
    -- then a Fowl-provided listener is set up on that peer. Any
    connections to this Fowl-provided listener cause a subchannel to
    be opened over the Wormhole, and a corresponding "connect()" call
    happens on the `fledge()` peer.

    Consider the "hello world" of networking software: chat. The
    "host" or server-side uses "netcat" while the "client" peer uses
    "telnet". So, we have to decide which peer is "the Host" and which
    peer is "the Guest".

    The initiating peer is "the Host": this peer sets up a wormhole
    connection, allocates and creates a magic code (printing it out),
    calls `fledge("chat")` and waits.

    It is waiting for the peer: the humans exchange the magic code,
    and "the Guest" peer: sets up a wormhole connection, uses the
    already-created magic code (completing the wormhole), and calls
    `roost("chat")`. It waits by calling `when_roosted("chat")`.

    If all goes well, the wormhole is completed, Dilation succeeds,
    and both peers proceed.  When `fledge("chat")` returns, "the Host"
    peer now has a `FowlChannelDaemonHere` instance. When
    `when_roosted("chat")` returns, "the Guest" peer now has a
    `FowlChannelDaemonThere` instance.

    Both peers can learn their appropriate ports: the Host peer runs
    `nc -l <port>` and the Guest peer runs `telnet localhost
    <port>`. Without having passed more arguments, these ports will be
    randomly assigned. They can be recovered from the
    `FowlChannelDaemonThere.connect_port` property on the Guest, and
    the `FowlChannelDaemonHere.listen_port` on the Host.
    """

    def __init__(self, reactor, wormhole, status_tracker):
        self._reactor = reactor
        self._wormhole = wormhole
        self._status_tracker = status_tracker

        self._services = dict()  # name -> FowlChannelDaemonHere: fledge() services.
        self._roosts = dict()  # name -> FowlChannelDaemonThere: permitted / listening services

        self._dilated = None  # DilatedWormhole once we're dilated
        self._when_ready = When()
        self._when_roosted = dict()  # maps "unique-name" to When() instances

    # XXX status listeners? probably makes more sense from "python
    # Twisted API" sense than the "Messages" objects -- although
    # though are good for something still i think
    #
    # ...so then does "status" have "an api", and the result is that
    # _it_ emits messages to listeners and updates "it's internal
    # status"?
    #
    # like, really we'd like "the status" to be @frozen and some kind
    # of like "status tracker" thing is what self._status is here and
    # it "evolve()s the @frozen status" and then sends it out to
    # listeners...

    async def dilate(self, **kwargs):
        """
        Must be called precisely once.

        Calls through to our wormhole's `dilate()` method after
        injecting our required subprotocol objects. Accepts all kwargs
        that `_DeferredWormhole.dilate()` takes.
        """
        if "on_status_update" in kwargs:
            # if upstream user sent a status_update we need a wrapper
            def wrapper(st):
                self._status_tracer.dilation_status(st)
                return wrapper.upstream(st)
            wrapper.upstream = kwargs["on_status_update"]
            kwargs["on_status_update"] = wrapper
        else:
            kwargs["on_status_update"] = self._status_tracker.dilation_status
        # add the default transit_relay_location= if it doesn't
        # already exist in the kwargs -- but note that if it's there
        # and None we should leave it alone (so upstream can decide
        # "we don't want a transit relay")
        if "transit_relay_location" not in kwargs:
            kwargs["transit_relay_location"] = TRANSIT_RELAY
        dilated = self._wormhole.dilate(**kwargs)
        self._set_dilated(dilated)
        # "dilated" is a DilatedWormhole instance

        # arrange to trigger our connected signal when the verifier
        # arrives
        def got_verifier(_verifier_bytes):
            self._when_ready.trigger(self._reactor, dilated)
        ensureDeferred(self._wormhole.get_verifier()).addCallback(got_verifier)

        await dilated.listener_for("fowl").listen(
            FowlSubprotocolListener(self._reactor, self, self._status_tracker)
        )
        await dilated.listener_for("fowl-commands").listen(
            FowlCommandsListener(self._reactor, self, self._status_tracker)
        )
        return dilated

    def roost(
            self,
            unique_name: str,
            local_endpoint: Optional[IStreamServerEndpoint]=None,
            remote_connect_port: Optional[int]=None,
    ) -> FowlChannelDaemonThere:
        """
        This adds a named service that is permitted here.

        This is the other side of 'fledge': we expect that the other
        peer will 'fledge' this service name (if it wants to use
        it). The daemon will be running on the side that calls
        'fledge'.

        To wait until a service is in use (which is possibly never, as
        we can't control what our peer decides to do) await the
        `when_roosted()` method for the same `unique_name`.
       """
        # todo: IPv4 vs IPv6?
        # todo: bind/connect addresses?
        # (currently can do both those by providing a local_endpoint "by hand", right?)
        if local_endpoint is None:
            local_endpoint = _LocalListeningEndpoint(self._reactor, None)
        channel = FowlChannelDaemonThere(
            unique_name,
            local_endpoint,
            remote_connect_port,
        )
        self._roosts[unique_name] = channel
        return channel

    async def when_roosted(self, unique_name):
        """
        Succeeds when the named service is listening.

        This only happens if our peer asks for this service-name via a
        call to `fledge` on their side -- so it may never happen.

        Usually you would only call this after a `roost()` call with the same `unique_name`.

        This method will only succeed after two things:
          - this peer has called `roost("foo")`;
          - and the other peer has called `fledge("foo")`
        """
        when = self._get_when_roosted(unique_name)
        value = await when.when_triggered()
        return value

    async def fledge(
            self,
            unique_name: str,
            local_connect_port: Optional[int]=None,
            remote_listen_port: Optional[int]=None,
            local_connect_addr: Optional[IPv4Address | IPv6Address]=None,
    ) -> FowlChannelDaemonHere:
        """
        Thinking about networking as 'server' or 'client', this method
        creates a listener on the far side, which will forward to the
        identical service on this side -- so the 'server'-style
        software runs on **this**_ peer.

        :param unique_name: must be unique across this Fowl session

        :param local_connect_port: where our Daemon will be
            listening. If not provided, an unused port will be found.

        :param remote_listen_portport: for some protocols, it matters
            what port the far-side is actually listening on (e.g. for
            Web endpoints). If this is provided, it requests this port
            on the peer. Only use this if your protocol really does
            require a particular listening port on the far-side peer
            -- that is, if one selected by the other peer cannot work
            for some reason.

        :param local_connect_addr: advanced use-cases my wish to
            specify non-localhost addresses to connect to -- this
            means we aren't _directly_ running the server-style
            software, but we know where that is. For example, one
            could use 192.168.2.3 or similar to function as a
            "jumpbox", forwarding traffic to another local machine.
        """
        if unique_name in self._roosts:
            raise ValueError(
                f"fledge({unique_name}) when we already have a roost for that name"
            )
        if unique_name in self._services:
            raise ValueError(
                f'Supposedly unique "{unique_name}" already in our services'
            )

        await self._when_ready.when_triggered()

        # XXX needs to be AFTER verifying-versions ... e.g. tie into state-machine?
        ep = self._dilated.connector_for("fowl-commands")
        fact = Factory.forProtocol(_SendFowlCommand)
        fact._reactor = self._reactor
        proto = await ep.connect(fact)

        data = await ensureDeferred(proto.send_command(unique_name, remote_listen_port))

        bsize = len(data)
        assert bsize >= 2, "expected at least 2 bytes"
        expected_size, = struct.unpack("!H", data[:2])
        assert bsize == expected_size + 2, "data has more than the message: {} vs {}: {}".format(bsize, expected_size + 2, repr(data[:55]))
        reply = msgpack.unpackb(data[2:])

        desired_port = reply.get("desired-port", None)

        if desired_port is not None:
            if local_connect_port is not None and local_connect_port != desired_port:
                raise RuntimeError(
                    f"Reply asked for port {desired_port} but we specified {local_connect_port}"
                )
        if not reply.get("listening", None):
            msg = reply.get("reason", "Unknown reason")
            raise RuntimeError(
                f'Service "{unique_name}" failed: {msg}'
            )

        if local_connect_port is None:
            local_connect_port = allocate_tcp_port() if desired_port is None else desired_port
        #XXX add connect address to added_local_service()
        self._status_tracker.added_local_service(unique_name, local_connect_port, remote_listen_port)

        # so if _we_ don't care about the listen-port, and the OTHER
        # peer does, it can/will communicate back in the reply -- so
        # we have to double-check if that's cool

        # okay, so _we_ know where we want this to connect back to, so
        # remember it in our services
        self._services[unique_name] = FowlChannelDaemonHere(
            unique_name,
            endpoint=TCP4ClientEndpoint(
                self._reactor,
                "localhost" if local_connect_addr is None else local_connect_addr,
                local_connect_port,
            ),
        )
        return self._services[unique_name]

    def subchannel_connector(self):
        return self._dilated.connector_for('fowl')

    def local_connect_endpoint(self, unique_name: str) -> IStreamClientEndpoint:
        """
        returns an endpoint that can be used to initiate a stream for the
        indicated service-name.
        """
        ch = self._services[unique_name]
        return ch.endpoint

    def listen_endpoint(self, name: str) -> IStreamServerEndpoint:
        """
        returns an endpoint upon which a local daemon can run. If you are
        running EXTERNAL daemon software (e.g. spawning a subprocess)
        you likely want "listen_port" -- or extract the port yourself.
        """
        # for this to work, either THIS side had to cal "fledge(name,
        # ..)" or the OTHER side had to call "roost(name, ...)"

    # helper methods follow (not public API)

    def _clean_roosts(self):
        """
        We are shutting down; perform cleanup on all roosts -- that is,
        close listening ports.
        """
        for channel in self._roosts.values():
            if channel.port:
                channel.port.stopListening()

    def _endpoint_for_service(self, unique_name, desired_port: Optional[int]=None):
        try:
            ep = self._roosts[unique_name].endpoint

        except KeyError:
            raise RuntimeError(
                f"No service permitted for name: {unique_name}"
            )

        # the contract here is that if the other side asks for a port,
        # it must be for a good reason (e.g. "it's Web stuff") and so
        # we use that port directly (and error out if we can't listen)
        if desired_port is not None:
            if isinstance(ep, _LocalListeningEndpoint):
                ep._set_desired_port(desired_port)

        return ep

    def _did_listen_locally(self, unique_name, port):
        when = self._get_when_roosted(unique_name)
        channel = self._roosts[unique_name]
        channel._is_listening(port)
        when.trigger(self._reactor, channel)
        return channel

#XXX FowlCoop is replacing FowlWormhole? or something?
    def _close_all_ports(self):
        for channel in self._roosts.values():
            if channel.port:
                channel.port.close()

    def _get_when_roosted(self, unique_name):
        """
        Internal helper.

        Returns the `When()` instance for a the given service (possibly
        creating it first).
        """
        try:
            when = self._when_roosted[unique_name]
        except KeyError:
            when = self._when_roosted[unique_name] = When()
        return when

    def _set_dilated(self, dilation: DilatedWormhole) -> None:
        """
        calls the underlying 'wormhole.dilate' with the passed-through
        args, and passes through the return API -- after adding
        anything it needs based on setup...?
        """
        if self._dilated is not None:
            raise ValueError(
                "dilated() may only be called once"
            )
        self._dilated = dilation


# originally from Tahoe-LAFS
@implementer(IStreamServerEndpoint)
@define
class CleanupEndpoint:
    """
    An ``IStreamServerEndpoint`` wrapper which closes a file descriptor if the
    wrapped endpoint is never used.

    :ivar IStreamServerEndpoint _wrapped: The wrapped endpoint.  The
        ``listen`` implementation is delegated to this object.

    :ivar int _fd: The file descriptor to close if ``listen`` is never called
        by the time this object is garbage collected.

    :ivar bool _listened: A flag recording whether or not ``listen`` has been
        called.
    """
    _wrapped: Any
    _fd: int
    _listened: bool = False

    def listen(self, protocolFactory):
        self._listened = True
        return self._wrapped.listen(protocolFactory)

    def __del__(self):
        """
        If ``listen`` was never called then close the file descriptor.
        """
        if not self._listened:
            os.close(self._fd)

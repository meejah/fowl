import os
import sys
import socket
from attr import define
from typing import Optional, Callable, Any

import msgpack
from twisted.internet.interfaces import IStreamClientEndpoint, IStreamServerEndpoint, IListeningPort, IReactorSocket, IReactorCore
from twisted.internet.endpoints import TCP4ServerEndpoint, TCP6ServerEndpoint
from twisted.internet.endpoints import TCP4ClientEndpoint, TCP6ClientEndpoint
from twisted.internet.endpoints import AdoptedStreamServerEndpoint
from twisted.internet.protocol import Factory
from twisted.python.reflect import requireModule
from twisted.python.runtime import platformType

from zope.interface import implementer

from wormhole._dilation.manager import DilatedWormhole
from wormhole.wormhole import IDeferredWormhole

from .observer import When
from ._proto import FowlSubprotocolListener, FowlCommandsListener, _SendFowlCommand, _pack_netstring, FowlNearToFar, LocalServer


# not available on Windows
fcntl = requireModule("fcntl")


@define
class FowlChannelDaemonHere:
    unique_name: str  # (must be UNIQUE across all of this Fowl session)
    endpoint: IStreamClientEndpoint  # how to connect to our daemon


@define
class FowlChannelDaemonThere:
    unique_name: str  # (must be UNIQUE across all of this Fowl session)
    endpoint: IStreamServerEndpoint  # where we're listening locally

    def get_listen_port(self) -> int:
        if isinstance(self.endpoint, TCP4ServerEndpoint):
            return self.endpoint._port
        elif isinstance(self.endpoint, TCP6ServerEndpoint):
            return self.endpoint._port
        raise ValueError(
            ".listener endpint is neither TCP4 nor TCP6 server"
        )


# XXX
# okay, so one side has to do .roost("name0", ...) and the other side
# has to do .fledge("name0", ...) with compatible args .. right?


def _create_local_listening_endpoint(reactor):
    """
    """
    return _LocalListeningEndpoint(reactor, None)


@implementer(IStreamServerEndpoint)
class _LocalListeningEndpoint:
    def __init__(self, reactor, desired_port):
        self._reactor = reactor
        self._desired_port = desired_port

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
                    s.bind(('', 0))
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
                    ####fileDescriptorResource.allocate()
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
            print("WE GOT PORTNUM", portnum)
            if portnum is None:
                # Get a random port number and fall through.  This is
                # necessary on Windows where Twisted doesn't offer
                # IReactorSocket.  This approach is error prone as it
                # is inherently a race: between when we set "portnum"
                # and when we call ".listen()", something else
                # (e.g. another process) could use this port.
                portnum = allocate_tcp_port()
            endpoint = TCP4ServerEndpoint(self._reactor, portnum, interface="localhost")
        port = await endpoint.listen(factory)
        return port


class FowlNest:
    """
    A chicken factory is a nest, right?

    Set up mappings for Fowl endpoints on either peer.

    Somewhat like the 'Builder' pattern, nothing will happen until
    some time after 'dilate()' is called. This method must be called
    exactly once.

    Unlike the Builder pattern, you can call the other methods either
    before or after 'dilate()'.

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

    `near_daemon()` is called when _this_ peer wishes to host the
    "daemon-style" software -- or the other peer could call
    `far_daemon()` from its side.

    Conversely, `far_daemon()` is called when the _other_ peer should
    host the "daemon-style" softare -- or that peer could arrange to
    call `near_daemon()` on its side.

    This amount of "symmetry" can be confusing. Please see the
    examples: git-withme and term-withme
    """

    def __init__(self, reactor, message_out=None):
        self._reactor = reactor
        self._services = dict()  # fledge() services.

        self._roosts = dict()  # name -> IStreamServerEndpoint

        self._dilated = None  # DilatedWormhole once we're dilated
        self._when_dilated = When()
        self._when_roosted = dict()  # maps "unique-name" to When() instances
        self._message_out = message_out

    # XXX for now, should be able to get rid of this from the API
    def message_out(self, msg):
        if self._message_out is not None:
            self._message_out(msg)

    def roost(
            self,
            unique_name: str,
            # XXX maybe just: local_listen_port: Optional[int]=None ???
            local_endpoint: Optional[IStreamServerEndpoint]=None,
    ) -> FowlChannelDaemonHere:
        """
        This adds a named service that is permitted here.

        This is the other side of 'fledge': we expect that the other
        peer will 'fledge' this service name (if it wants to use
        it). The daemon will be running on the side that calls
        'fledge'.

        To wait until a service is in use (which is possibly never, as
        we can't control what our peer decides to do) use the
        `when_roosted()` method.
        """
        # XXX IPv4 vs IPv6?
        if local_endpoint is None:
            local_endpoint = _create_local_listening_endpoint(self._reactor)
        self._roosts[unique_name] = local_endpoint

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
            local_listen_port: Optional[int]=None,
            desired_remote_port: Optional[int]=None,
    ) -> FowlChannelDaemonHere:
        """
        Thinking about networking as 'server' or 'client', this method
        creates a listener on the far side, which will forward to the
        identical service on this side -- so the 'server'-style
        software runs on _this_ peer.

        :param unique_name: must be unique across this Fowl session

        :param local_listen_port: where our Daemon will be
            listening. If not provided, an unused port will be found.

        :param desired_remote_port: for some protocols, it matters
            what port the far-side is actually listening on (e.g. for
            Web endpoints). If this is provided, it requests this port
            on the peer. Only use this if your protocol really does
            require a particular listening port on the far-side peer
            -- that is, if one selected by the other peer cannot work
            for some reason.
        """
        print("FLEDGE", unique_name)
        if local_listen_port is None:
            local_listen_port = allocate_tcp_port()
        ep = self._dilated.subprotocol_connector_for("fowl-commands")
        fact = Factory.forProtocol(_SendFowlCommand)
        fact._reactor = self._reactor
        proto = await ep.connect(fact)
        await proto.when_connected()

        #XXX should be method on _SendFowlCommand
        proto.transport.write(
            _pack_netstring(
                    msgpack.packb({
                        "kind": "request-listener",
                        "unique-name": unique_name,
                        "listen-port": desired_remote_port,
                    })
            )
        )

        reply = await proto.next_message()
        print("REPLY to fledge()", reply)
        # okay, so _we_ know where we want this to connect back to, so
        # remember it in our services
        if unique_name in self._services:
            raise ValueError(
                f'Supposedly unique "{unique_name}" already in our services'
            )
        self._services[unique_name] = FowlChannelDaemonHere(
            unique_name,
            endpoint=TCP4ClientEndpoint(self._reactor, "localhost", local_listen_port),
        )
        return self._services[unique_name]

    def subchannel_connector(self):
        return self._dilated.subprotocol_connector_for('fowl')

    def local_connect_endpoint(self, unique_name: str) -> IStreamClientEndpoint:
        """
        returns an endpoint that can be used to initiate a stream for the
        indicated service-name.
        """
        print("connect_endpoint", sorted(self._services.keys()))
        ch = self._services[unique_name]
        print("channel", ch)
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

    def _endpoint_for_service(self, unique_name, desired_port: Optional[int]=None):
        try:
            ep = self._roosts[unique_name]
            # if "ep" is whatever we create for 'delayed choose random
            # port' endpoint, then we can pass it the "port_hint"
            # somehow, and it can use that as the first guess
            if desired_port is not None:
                if isinstance(ep, _LocalListeningEndpoint):
                    print("SETTING DESIRED PORT", desired_port)
                    ep._set_desired_port(desired_port)

            # XXX for Web stuff we might want 'force_hint=True' or
            # something to say it's not a 'desired' port, it's a
            # requirement?  (Or maybe we just make the argument itself
            # that -- if provided, it's required)
        except KeyError:
            raise RuntimeError(
                f"No service permitted for name: {unique_name}"
            )
        return ep

    def _did_listen_locally(self, unique_name, port):
        when = self._get_when_roosted(unique_name)
        when.trigger(self._reactor, port)

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
                "dilated() may only be called once per next"
            )
        self._dilated = dilation
        self._when_dilated.trigger(self._reactor, self._dilated)


# temp: just a singleton for now
# ...maybe we need a "Coop" that contains "Nests"?
# ...or maybe the whole Nest thing is just dumb?

_nest = None

def create(reactor):
    global _nest
    if _nest is None:
        _nest = FowlNest(reactor)
    return _nest


def build_nests(
        reactor: IReactorCore,
        wormhole: IDeferredWormhole,
        nests: list[FowlNest],
        extra_subprotocols: Optional[dict]=None,
        **kwargs,  # everything dilate() accepts
) -> DilatedWormhole:
    """
    Friendly helper to inject one or more FowlNests (e.g. from several
    Fowl-using plugins) into a wormhole dilate() call properly --
    along with any extra subprotocols (e.g. not using Fowl) that your
    application may require.
    """
    subprotocols = dict()
    if extra_subprotocols:
        subprotocols.update(extra_subprotocols)

    # XXX bug: we're overwriting some Nest's subprotocol -- need singleton

    # XXX double-check all the reactors in all the nests match this
    # reactor? or magically get it out of those?
    subprotocols["fowl"] = FowlSubprotocolListener(reactor, nests[0])
    subprotocols["fowl-commands"] = FowlCommandsListener(reactor, nests[0])

    # so we need ONE of each kind of listener, tied back to ... the
    # services that each Nest has requested? so instead of
    # "build_subprotocols()" we need to give "the" command listener
    # all FowlNest instances?

    dilated = wormhole.dilate(subprotocols, **kwargs)

    for nest in nests:
        nest._set_dilated(dilated)

    # "dilated" is a DilatedWormhole instance
    return dilated


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
        print("LISTEN", self._wrapped, protocolFactory)
        return self._wrapped.listen(protocolFactory)

    def __del__(self):
        """
        If ``listen`` was never called then close the file descriptor.
        """
        if not self._listened:
            os.close(self._fd)
            ####fileDescriptorResource.release()


# originally from Foolscap
def allocate_tcp_port():
    """Return an (integer) available TCP port on localhost. This briefly
    listens on the port in question, then closes it right away."""

    # Making this work correctly on multiple OSes is non-trivial:
    # * on OS-X:
    #   * Binding the test socket to 127.0.0.1 lets the kernel give us a
    #     LISTEN port that some other process is using, if they bound it to
    #     ANY (0.0.0.0). These will fail when we attempt to
    #     listen(bind=0.0.0.0) ourselves
    #   * Binding the test socket to 0.0.0.0 lets the kernel give us LISTEN
    #     ports bound to 127.0.0.1, although then our subsequent listen()
    #     call usually succeeds.
    #   * In both cases, the kernel can give us a port that's in use by the
    #     near side of an ESTABLISHED socket. If the process which owns that
    #     socket is not owned by the same user as us, listen() will fail.
    #   * Doing a listen() right away (on the kernel-allocated socket)
    #     succeeds, but a subsequent listen() on a new socket (bound to
    #     the same port) will fail.
    # * on Linux:
    #   * The kernel never gives us a port in use by a LISTEN socket, whether
    #     we bind the test socket to 127.0.0.1 or 0.0.0.0
    #   * Binding it to 127.0.0.1 does let the kernel give us ports used in
    #     an ESTABLISHED connection. Our listen() will fail regardless of who
    #     owns that socket. (note that we are using SO_REUSEADDR but not
    #     SO_REUSEPORT, which would probably affect things).
    #

    #
    # So to make this work properly everywhere, allocate_tcp_port() needs two
    # phases: first we allocate a port (with 0.0.0.0), then we close that
    # socket, then we open a second socket, bind the second socket to the
    # same port, then try to listen. If the listen() fails, we loop back and
    # try again.

    # In addition, on at least OS-X, the kernel will give us a port that's in
    # use by some other process, when that process has bound it to 127.0.0.1,
    # and our bind/listen (to 0.0.0.0) will succeed, but a subsequent caller
    # who tries to bind it to 127.0.0.1 will get an error in listen(). So we
    # must actually test the proposed socket twice: once bound to 0.0.0.0,
    # and again bound to 127.0.0.1. This probably isn't complete for
    # applications which bind to a specific outward-facing interface, but I'm
    # ok with that; anything other than 0.0.0.0 or 127.0.0.1 is likely to use
    # manually-selected ports, assigned by the user or sysadmin.

    # Ideally we'd refrain from doing listen(), to minimize impact on the
    # system, and we'd bind the port to 127.0.0.1, to avoid making it look
    # like we're accepting data from the outside world (in situations where
    # we're going to end up binding the port to 127.0.0.1 anyways). But for
    # the above reasons, neither would work. We *do* add SO_REUSEADDR, to
    # make sure our lingering socket won't prevent our caller from opening it
    # themselves in a few moments (note that Twisted's
    # tcp.Port.createInternetSocket sets SO_REUSEADDR, among other flags).

    count = 0
    while True:
        s = _make_socket()
        s.bind(("0.0.0.0", 0))
        port = s.getsockname()[1]
        s.close()

        s = _make_socket()
        try:
            s.bind(("0.0.0.0", port))
            s.listen(5) # this is what sometimes fails
            s.close()
            s = _make_socket()
            s.bind(("127.0.0.1", port))
            s.listen(5)
            s.close()
            return port
        except socket.error:
            s.close()
            count += 1
            if count > 100:
                raise
            # try again


def _make_socket():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if platformType == "posix" and sys.platform != "cygwin":
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    return s


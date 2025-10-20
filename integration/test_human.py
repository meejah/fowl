import re
import socket

import pytest_twisted
from twisted.internet.interfaces import ITransport
from twisted.internet.protocol import ProcessProtocol, Factory, Protocol
from twisted.internet.task import deferLater
from twisted.internet.defer import Deferred
from twisted.internet.endpoints import serverFromString, clientFromString
from attrs import define

from util import run_service

# since the src/fowl/test/test_forward tests exercise the underlying
# "fowld" functionality (minus the entry-point), this tests the
# "user-friendly" frontend.


@define
class _Fowl:
    transport: ITransport
    protocol: ProcessProtocol


class _FowlProtocol(ProcessProtocol):
    """
    This speaks to an underlying ``fowl`` sub-process.
    """

    def __init__(self, reactor):
        self._reactor = reactor
        self.exited = Deferred()
        self._data = ""
        self._waiting = []

    def processEnded(self, reason):
        self.exited.callback(None)

    async def have_line(self, regex):
        d = Deferred()
        self._waiting.append((d, regex))
        self._maybe_trigger()
        return await d

    def _maybe_trigger(self):
        lines = [
            line
            for line in self._data.split("\n")
            if line.strip()
        ]
        for i, item in enumerate(self._waiting):
            d, regex = item
            for line in lines:
                m = re.match(regex, line)
                if m:
                    del self._waiting[i]
                    d.callback(m)
                    return

    def childDataReceived(self, childFD, data):
        self._data += data.decode("utf8")
###        print(self._data)
        self._maybe_trigger()


async def fowl(reactor, request, subcommand, *extra_args, mailbox=None):
    """
    Run `fowl` with a given subcommand
    """

    args = [
        "fowl.cli",
    ]
    if mailbox is not None:
        args.extend([
            "--mailbox", mailbox,
        ])

    args.append(subcommand)
    args.extend(extra_args)
    proto = _FowlProtocol(reactor)
    transport = await run_service(
        reactor,
        request,
        args=args,
        protocol=proto,
    )
    return _Fowl(transport, proto)


class Echo(Protocol):
    def dataReceived(self, data):
        self.transport.write(data)


class Hello(Protocol):
    def connectionMade(self):
        self._data = b""
        self.transport.write(b"Hello, world!")

    def dataReceived(self, data):
        self._data += data


# could use hypothesis to try 'a bunch of ports' but fixed ports seem
# easier to reason about to me
@pytest_twisted.ensureDeferred
async def test_human(reactor, request, wormhole):
    """
    """
    f0 = await fowl(reactor, request, "--client", "zero:7000:remote-connect=7007", "--service", "one:8008:listen=8000", mailbox=wormhole.url)
    m = await f0.protocol.have_line(".*code: ([-0-9a-z]*) ")
    code = m.group(1)
    print(f"saw code: {code}")

    f1 = await fowl(reactor, request, "--service", "zero", "--client", "one", code, mailbox=wormhole.url)

    if False:
        # XXX can we pull the verifiers out easily?
        # verifiers match
        m = await f0.protocol.have_line("Verifier: (.*)")
        f0_verify = m.group(1)

        m = await f1.protocol.have_line("Verifier: (.*)")
        f1_verify = m.group(1)
        assert f1_verify == f0_verify, "Verifiers don't match"

    # wait until we see one side listening
    while True:
        await deferLater(reactor, 0.5, lambda: None)
        print("Waiting for at least one listener")
        if "🧙" in f0.protocol._data or "🧙" in f1.protocol._data:
            print("see one side listening")
            break

    print("Making a local connection")
    port = await serverFromString(reactor, "tcp:8008:interface=localhost").listen(
        Factory.forProtocol(Echo)
    )
    request.addfinalizer(lambda:port.stopListening())
    print("  listening on 8008")

    ep1 = clientFromString(reactor, "tcp:localhost:8000")
    print("  connecting to 8000")
    proto = await ep1.connect(Factory.forProtocol(Hello))
    print("  sending data, awaiting reply")

    for _ in range(5):
        await deferLater(reactor, 0.2, lambda: None)
        if proto._data == b"Hello, world!":
            break
    print(f"  got {len(proto._data)} bytes reply")
    assert proto._data == b"Hello, world!", "Did not see expected echo reply across wormhole"


def _get_our_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        # doesn't even have to be reachable
        s.connect(('10.254.254.254', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP


@pytest_twisted.ensureDeferred
async def test_non_localhost(reactor, request, wormhole):
    """
    """
    # attempt to discover "our" IP address -- so we can attempt to
    # connect to it, but not via localhost
    ours = _get_our_ip()
    f0 = await fowl(reactor, request, "--local", f"foo:8111:bind={ours}:remote-connect=8222", mailbox=wormhole.url)
    m = await f0.protocol.have_line(".*code: ([-0-9a-z]*) ")
    code = m.group(1)
    print(f"saw code: {code}")

    f1 = await fowl(reactor, request, "--remote", f"foo:8222:address={ours}", code, mailbox=wormhole.url)

    # wait until we see one side listening
    while True:
        await deferLater(reactor, 0.5, lambda: None)
        print("Waiting for at least one listener")
        if "🧙" in f0.protocol._data or "🧙" in f1.protocol._data:
            print("see one side listening")
            break

    port = await serverFromString(reactor, f"tcp:8222:interface={ours}").listen(
        Factory.forProtocol(Echo)
    )
    request.addfinalizer(lambda:port.stopListening())
    print(f"  listening on 8222:interface={ours}")

    ep1 = clientFromString(reactor, f"tcp:{ours}:8111")
    print("  connecting to 8111")
    proto = await ep1.connect(Factory.forProtocol(Hello))
    print("  sending data, awaiting reply")

    for _ in range(5):
        await deferLater(reactor, 0.2, lambda: None)
        if proto._data == b"Hello, world!":
            break
    print(f"  got {len(proto._data)} bytes reply")
    assert proto._data == b"Hello, world!", "Did not see expected echo reply across wormhole"


@pytest_twisted.ensureDeferred
async def test_non_localhost_backwards(reactor, request, wormhole):
    """
    Same as above test but the 'other way' around
    """
    ours = _get_our_ip()
    f0 = await fowl(reactor, request, "--remote", f"quux:8444:address={ours}:listen=8333", mailbox=wormhole.url)
    m = await f0.protocol.have_line(".*code: ([-0-9a-z]*) ")
    code = m.group(1)
    print(f"saw code: {code}")

    f1 = await fowl(reactor, request, "--local", f"quux:8333", code, mailbox=wormhole.url)

    # wait until we see one side listening
    while True:
        await deferLater(reactor, 0.5, lambda: None)
        if "🧙" in f0.protocol._data and "🧙" in f1.protocol._data:
            print("both sides have a service")
            break

    port = await serverFromString(reactor, f"tcp:8444:interface={ours}").listen(
        Factory.forProtocol(Echo)
    )
    request.addfinalizer(lambda:port.stopListening())
    print(f"  listening on 8444:interface={ours}")

    ep1 = clientFromString(reactor, "tcp:localhost:8333")
    print(f"  connecting to localhost:8333")
    proto = await ep1.connect(Factory.forProtocol(Hello))
    print("  sending data, awaiting reply")

    for _ in range(5):
        await deferLater(reactor, 0.2, lambda: None)
        if proto._data == b"Hello, world!":
            break
    print(f"  got {len(proto._data)} bytes reply")
    assert proto._data == b"Hello, world!", "Did not see expected echo reply across wormhole"

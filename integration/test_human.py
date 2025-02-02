import re
import sys
import json
import socket
from collections import defaultdict

import pytest_twisted
from twisted.internet.interfaces import ITransport
from twisted.internet.protocol import ProcessProtocol, Factory, Protocol
from twisted.internet.task import deferLater
from twisted.internet.error import ProcessExitedAlready, ProcessDone
from twisted.internet.defer import Deferred
from twisted.internet.endpoints import serverFromString, clientFromString
from attrs import define

from util import run_service
from fowl.observer import Next

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
    f0 = await fowl(reactor, request, "--local", "8000:8008", "--remote", "7000:7007", mailbox=wormhole.url)
    await f0.protocol.have_line("Connected.")
    m = await f0.protocol.have_line(".* code: (.*).*")
    code = m.group(1)

    f1 = await fowl(reactor, request, "--allow-connect", "localhost:8008", "--allow-listen", "7000", code, mailbox=wormhole.url)

    # both should say they're connected
    await f0.protocol.have_line("Peer is connected.")
    await f1.protocol.have_line("Peer is connected.")

    # verifiers match
    m = await f0.protocol.have_line("Verifier: (.*)")
    f0_verify = m.group(1)

    m = await f1.protocol.have_line("Verifier: (.*)")
    f1_verify = m.group(1)
    assert f1_verify == f0_verify, "Verifiers don't match"

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
    f0 = await fowl(reactor, request, "--local", f"127.0.0.1:8111:{ours}:8222", mailbox=wormhole.url)
    await f0.protocol.have_line("Connected.")
    m = await f0.protocol.have_line(".* code: (.*).*")
    code = m.group(1)

    f1 = await fowl(reactor, request, "--allow-connect", f"{ours}:8222", code, mailbox=wormhole.url)

    # both should say they're connected
    await f0.protocol.have_line("Peer is connected.")
    await f1.protocol.have_line("Peer is connected.")

    # verifiers match
    m = await f0.protocol.have_line("Verifier: (.*)")
    f0_verify = m.group(1)

    m = await f1.protocol.have_line("Verifier: (.*)")
    f1_verify = m.group(1)
    assert f1_verify == f0_verify, "Verifiers don't match"

    port = await serverFromString(reactor, f"tcp:8222:interface={ours}").listen(
        Factory.forProtocol(Echo)
    )
    request.addfinalizer(lambda:port.stopListening())
    print(f"  listening on 8222:interface={ours}")

    ep1 = clientFromString(reactor, "tcp:localhost:8111")
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
    f0 = await fowl(reactor, request, "--remote", f"127.0.0.1:8333:{ours}:8444", "--remote", f"{ours}:8555:8666", mailbox=wormhole.url)
    await f0.protocol.have_line("Connected.")
    m = await f0.protocol.have_line(".* code: (.*).*")
    code = m.group(1)

    f1 = await fowl(reactor, request, "--allow-listen", f"8333", "--allow-listen", f"{ours}:8555", code, mailbox=wormhole.url)

    # both should say they're connected
    await f0.protocol.have_line("Peer is connected.")
    await f1.protocol.have_line("Peer is connected.")

    # verifiers match
    m = await f0.protocol.have_line("Verifier: (.*)")
    f0_verify = m.group(1)

    m = await f1.protocol.have_line("Verifier: (.*)")
    f1_verify = m.group(1)
    assert f1_verify == f0_verify, "Verifiers don't match"

    port = await serverFromString(reactor, f"tcp:8444:interface={ours}").listen(
        Factory.forProtocol(Echo)
    )
    request.addfinalizer(lambda:port.stopListening())
    print(f"  listening on 8444:interface={ours}")

    # wait until our peer has listened etc
    peer_alive = False
    start = reactor.seconds()
    while not peer_alive:
        await deferLater(reactor, 0.2, lambda: None)
        if "Peer is listening" in f0.protocol._data:
            peer_alive = True
        if reactor.seconds() - start > 10.0:
            assert False, "Waited 5 seconds for peer to listen and it did not"

    ep1 = clientFromString(reactor, "tcp:localhost:8333")
    print("  connecting to 8333")
    proto = await ep1.connect(Factory.forProtocol(Hello))
    print("  sending data, awaiting reply")

    for _ in range(5):
        await deferLater(reactor, 0.2, lambda: None)
        if proto._data == b"Hello, world!":
            break
    print(f"  got {len(proto._data)} bytes reply")
    assert proto._data == b"Hello, world!", "Did not see expected echo reply across wormhole"

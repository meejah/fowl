
import pytest_twisted

#from twisted.internet.protocol import ProtocolBase
from zope.interface import implementer
from twisted.internet.interfaces import IProcessProtocol
from twisted.internet.protocol import ProcessProtocol
from twisted.internet.endpoints import serverFromString, clientFromString
from twisted.internet.task import deferLater
from hypothesis.strategies import integers, sampled_from, one_of, ip_addresses
from hypothesis import given
import click
import sys
import os
import signal
from fowl.observer import When, Framer
from fowl.test.util import ServerFactory, ClientFactory
from fowl.cli import _to_port


@implementer(IProcessProtocol)
class CollectStreams(ProcessProtocol):

    def __init__(self, reactor):
        self._reactor = reactor
        self._streams = {
            1: b"",
            2: b"",
        }
        self._done = When()
        self._lines = Framer(reactor)

    def when_done(self):
        return self._done.when_triggered()

    def next_line(self):
        return self._lines.next_message()

    def childDataReceived(self, fd, data):
        self._streams[fd] += data
        if fd == 1:
            self._lines.data_received(data)

    def processExited(self, reason):
        pass  #reason == Failure

    def processEnded(self, reason):
        self._done.trigger(self._reactor, reason)


# maybe Hypothesis better, via strategies.binary() ?
@pytest_twisted.ensureDeferred
async def test_happy_path(reactor, request, mailbox):
    """
    One side invites, other accepts.

    Some commands are executed.
    Improvement: let Hypothesis make up commands, order, etc (how to assert?)
    """

    print("Starting invite side", os.environ.get("COVERAGE_PROCESS_STARTUP", "no startup"))

    invite_proto = CollectStreams(reactor)
    invite = reactor.spawnProcess(
        invite_proto,
        sys.executable,
        [
            "python", "-u", "-m", "fowl.cli",
            "--mailbox", mailbox.url,
            "--remote", "test:2121:listen=2222",
        ],
        env=os.environ,
    )
    request.addfinalizer(lambda:invite.signalProcess(signal.SIGKILL))

    import re
    x = re.compile(b"code: (.*)\x1b")
    code = None
    while not code:
        await deferLater(reactor, .4, lambda: None)
        if m := x.search(invite_proto._streams[1]):
            code = m.group(1).decode("utf8")

    print(f"Detected code: {code}")

    accept_proto = CollectStreams(reactor)
    accept = reactor.spawnProcess(
        accept_proto,
        sys.executable,
        [
            "python", "-u", "-m", "fowl.cli",
            "--mailbox", mailbox.url,
            "--local", "test:2222",
            code,
        ],
        env=os.environ,
    )
    request.addfinalizer(lambda:accept.signalProcess(signal.SIGKILL))

    print("Starting accept side")

    while True:
        await deferLater(reactor, .4, lambda: None)
        if "🧙".encode("utf8") in invite_proto._streams[1] \
           and "🧙".encode("utf8") in accept_proto._streams[1]:
            print("both sides set up")
            break
        os.write(0, invite_proto._streams[1])
        os.write(0, accept_proto._streams[1])

    # now that they are connected, and one side is listening -- we can
    # ourselves listen on the "connect" port and connect on the
    # "listen" port -- that is, listen on 2121 (where there is no
    # listener) and connect on 2222 (where this test is listening)

    listener = ServerFactory(reactor)
    await serverFromString(reactor, "tcp:2121:interface=localhost").listen(listener)  # returns server_port

    client = clientFromString(reactor, "tcp:localhost:2222")
    client_proto = await client.connect(ClientFactory(reactor))
    server = await listener.next_client()

    datasize = 1234
    data = os.urandom(datasize)

    client_proto.send(data)
    msg = await server.next_message(len(data))
    assert msg == data, "Incorrect data transfer"

    print("done")


@given(integers(min_value=1, max_value=65535))
def test_helper_to_port(port):
    assert(_to_port(port) == port)
    assert(_to_port(str(port)) == port)


@given(one_of(integers(max_value=0), integers(min_value=65536)))
def test_helper_to_port_invalid(port):
    try:
        _to_port(port)
        assert False, "Should raise exception"
    except click.UsageError:
        pass


@given(integers(min_value=1, max_value=65535))
def test_specifiers_one_port(port):
    cmd = f"{port}"
    assert _specifier_to_tuples(cmd) == ("localhost", port, "localhost", port)


@given(
    integers(min_value=1, max_value=65535),
    integers(min_value=1, max_value=65535),
)
def test_specifiers_two_ports(port0, port1):
    cmd = f"{port0}:{port1}"
    assert _specifier_to_tuples(cmd) == ("localhost", port0, "localhost", port1)


@given(
    integers(min_value=1, max_value=65535),
    integers(min_value=1, max_value=65535),
    ip_addresses(v=4),  # do not support IPv6 yet
)
def test_specifiers_two_ports_one_ip(port0, port1, ip):
    if ip.version == 4:
        cmd = f"{ip}:{port0}:{port1}"
    else:
        cmd = f"[{ip}]:{port0}:{port1}"
    assert _specifier_to_tuples(cmd) == (str(ip), port0, "localhost", port1)


@given(
    integers(min_value=1, max_value=65535),
    integers(min_value=1, max_value=65535),
    ip_addresses(v=4),  # do not support IPv6 yet
    ip_addresses(v=4),  # do not support IPv6 yet
)
def test_specifiers_two_ports_two_ips(port0, port1, ip0, ip1):
    cmd = f"{ip0}:{port0}:{ip1}:{port1}"
    assert _specifier_to_tuples(cmd) == (str(ip0), port0, str(ip1), port1)


@given(
    integers(min_value=1, max_value=65535),
    integers(min_value=1, max_value=65535),
    ip_addresses(v=6),
    ip_addresses(v=6),
    sampled_from([True, False]),
)
def test_specifiers_unsupported_v6(port0, port1, ip0, ip1, wrap):
    if wrap:
        cmd = f"[{ip0}]:{port0}:[{ip1}]:{port1}"
    else:
        cmd = f"{ip0}:{port0}:{ip1}:{port1}"
    try:
        assert _specifier_to_tuples(cmd) == (str(ip0), port0, str(ip1), port1)
    except RuntimeError:
        pass
    except ValueError:
        pass

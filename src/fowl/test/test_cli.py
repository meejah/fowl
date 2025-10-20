import re

import pytest
import pytest_twisted

#from twisted.internet.protocol import ProtocolBase
from zope.interface import implementer
from twisted.internet.interfaces import IProcessProtocol
from twisted.internet.protocol import ProcessProtocol
from twisted.internet.endpoints import serverFromString, clientFromString
from twisted.internet.task import deferLater
from hypothesis.strategies import integers, one_of, ip_addresses, text
from hypothesis import given, assume
import click
import sys
import os
import signal
from fowl.observer import When, Framer
from fowl.test.util import ServerFactory, ClientFactory
from fowl.cli import _to_port, RemoteSpecifier
from fowl.messages import RemoteListener


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

    code_matcher = re.compile(b"code: ([-0-9a-z]*) ")
    code = None
    while not code:
        await deferLater(reactor, .4, lambda: None)
        if m := code_matcher.search(invite_proto._streams[1]):
            code = m.group(1).decode("utf8")
            code = code.strip()

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

    for i in range(5):
        await deferLater(reactor, 2.5, lambda: None)
        if "🧙".encode("utf8") in invite_proto._streams[1] \
           and "🧙".encode("utf8") in accept_proto._streams[1]:
            print("both sides set up")
            break
        if False:
            # debug actual output
            os.write(0, invite_proto._streams[1])
            os.write(0, accept_proto._streams[1])
    else:
        assert False, "failed to see both sides set up"

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


@given(
    text(min_size=1),
    integers(min_value=1, max_value=65535),
)
def test_specifiers_one_port(name, port):
    assume('[' not in name)
    assume(']' not in name)
    assume(':' not in name)
    spec = RemoteSpecifier.parse(f"{name}:{port}")
    assert spec.to_remote() == RemoteListener(
        name=name,
        local_connect_port=port,
    )


@given(
    text(min_size=1),
    integers(min_value=1, max_value=65535),
    integers(min_value=1, max_value=65535),
)
def test_specifiers_two_ports(name, port0, port1):
    assume('[' not in name)
    assume(']' not in name)
    assume(':' not in name)
    spec = RemoteSpecifier.parse(f"{name}:{port0}:listen={port1}")
    assert spec.to_remote() == RemoteListener(
        name=name,
        local_connect_port=port0,
        remote_listen_port=port1,
    )


@given(
    text(min_size=1),
    integers(min_value=1, max_value=65535),
    integers(min_value=1, max_value=65535),
    ip_addresses(v=4),  # do not support IPv6 yet
)
def test_specifiers_two_ports_one_ip(name, port0, port1, ip):
    assume('[' not in name)
    assume(']' not in name)
    assume(':' not in name)
    if ip.version == 4:
        cmd = f"{name}:{port0}:listen={port1}:address={ip}"
    else:
        cmd = f"{name}:{port0}:listen={port1}:address=[{ip}]"
    spec = RemoteSpecifier.parse(cmd)
    assert spec.to_remote() == RemoteListener(
        name=name,
        local_connect_port=port0,
        remote_listen_port=port1,
        connect_address=str(ip),
    )


@given(
    text(min_size=1),
    integers(min_value=1, max_value=65535),
    integers(min_value=1, max_value=65535),
    ip_addresses(v=6),
)
def test_specifiers_unsupported_v6(name, port0, port1, ip):
    cmd = f"{name}:{port0}:listen={port1}:address=[{ip}]"
    with pytest.raises(RuntimeError):
        assert RemoteSpecifier.parse(cmd)

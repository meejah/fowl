import os
import sys
import shutil
import re
import json
from functools import partial
from twisted.internet.protocol import Factory
from twisted.internet.protocol import ProcessProtocol
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.internet.interfaces import IProcessProtocol
from twisted.internet.task import deferLater
from zope.interface import implementer
import pytest
import pytest_twisted

from fowl.observer import When, Framer
from fowl.tcp import allocate_tcp_port
from fowl._proto import parse_fowld_output, fowld_command_to_json
from fowl import messages
from .util import _MagicTextProtocol, _cleanup_service_process


@implementer(IProcessProtocol)
class FowlD(ProcessProtocol):

    def __init__(self, reactor):
        self._reactor = reactor
        self._done = When()
        self._lines = Framer(reactor)

    def when_done(self):
        return self._done.when_triggered()

    async def next_message(self):
        line = await self._lines.next_message()
        msg, _ = parse_fowld_output(line)
        return msg

    def write_message(self, fowldcmd):
        data = json.dumps(fowld_command_to_json(fowldcmd))
        data = data + "\n"
        self.transport.write(data.encode("utf8"))

    def childDataReceived(self, fd, data):
        if fd == 1:
            self._lines.data_received(data)

    def processExited(self, reason):
        pass  #reason == Failure

    def processEnded(self, reason):
        self._done.trigger(self._reactor, reason)


@pytest_twisted.async_yield_fixture()
async def iperf3_server(reactor, request):
    args = ["iperf3", "-V", "-4", "-s", "localhost", "-p", "54321"]
    logs = []
    protocol = _MagicTextProtocol("listening on", logs.append)
    exe = shutil.which("iperf3")
    if exe is None:
        raise pytest.skip("no iperf3 found")
    process = reactor.spawnProcess(
        protocol,
        exe,
        args,
        env=os.environ,
    )
    request.addfinalizer(partial(_cleanup_service_process, process, protocol.exited))
    await deferLater(reactor, 1.0, lambda: None)
    ##await protocol.magic_seen
    yield protocol


async def iperf3_client(reactor, request):
    args = ["iperf3", "-4", "-c", "localhost", "-p", "12345", "-n", "1G"]
    logs = []
    protocol = _MagicTextProtocol("iperf Done", logs.append)
    exe = shutil.which("iperf3")

    env = os.environ.copy()
    env['PYTHONUNBUFFERED'] = '1'
    for k, v in env.items():
        if 'COV' in k:
            print(k, v)
    process = reactor.spawnProcess(
        protocol,
        exe,
        args,
        env=env,
    )
    request.addfinalizer(partial(_cleanup_service_process, process, protocol.exited))
    await protocol.magic_seen
    return logs


@pytest_twisted.ensureDeferred()
async def test_performance(reactor, request, mailbox, iperf3_server):
    """
    Start up an iperf3 test as per:
    https://github.com/magic-wormhole/fowl/issues/34

    Doesn't do anything if iperf3 is not found
    """
    print("iperf3 service running")
    invite_proto = FowlD(reactor)
    invite = reactor.spawnProcess(
        invite_proto,
        sys.executable,
        [
            "python", "-u", "-m", "fowl",
            "--mailbox", mailbox.url
        ],
        env=os.environ,
    )
    request.addfinalizer(lambda:invite.signalProcess("KILL"))

    m = await invite_proto.next_message()
    print("I: welcome", m.url)
    invite_proto.write_message(messages.AllocateCode())
    m = await invite_proto.next_message()
    code = m.code
    print("I: allocated code", code)

    accept_proto = FowlD(reactor)
    accept = reactor.spawnProcess(
        accept_proto,
        sys.executable,
        [
            "python", "-u", "-m", "fowl",
            "--mailbox", mailbox.url
        ],
        env=os.environ,
    )
    request.addfinalizer(lambda:accept.signalProcess("KILL"))

    m = await accept_proto.next_message()
    print("A: welcome", m.url)
    accept_proto.write_message(messages.SetCode(code))

    m = await accept_proto.next_message()
    print("A: code", m.code)

    invite_proto.write_message(messages.LocalListener("iperf", 12345))
    accept_proto.write_message(messages.RemoteListener("iperf", local_connect_port=54321))

    m = await invite_proto.next_message()
    print("I: peer", m.verifier)
    m = await accept_proto.next_message()
    print("A: peer", m.verifier)
    m = await accept_proto.next_message()
    print("A: awaiting connect", m.local_port)

    print("start iperf3 client")
    start = reactor.seconds()
    logs = await iperf3_client(reactor, request)
    elapsed = reactor.seconds() - start
    print("elapsed", elapsed)
    bps = 1*1024*1024*1024 / elapsed
    print("bytes per second", bps)
    print("MiB/s", bps / (1024*1024.0))

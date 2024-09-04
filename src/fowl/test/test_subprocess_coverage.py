import os
import sys
import signal
from twisted.internet.task import deferLater
from twisted.internet.protocol import ProcessProtocol, Protocol, Factory
import pytest_twisted


class CollectStreams(ProcessProtocol):

    def __init__(self, reactor):
        self._reactor = reactor
        self._streams = {
            1: b"",
            2: b"",
        }

    def childDataReceived(self, fd, data):
        self._streams[fd] += data
        if fd == 1:
            self._lines.data_received(data)

@pytest_twisted.ensureDeferred
async def test_foo(reactor):
    accept_proto = CollectStreams(reactor)
    accept = reactor.spawnProcess(
        accept_proto,
        sys.executable,
        [
##            "python", "-u", "-m", "fowl.cli",
            "python", "-u", "-m", "coverage", "run", "-m", "fowl.cli",
            "--mailbox", "ws://localhost:4000/v1",
            "--allow-listen", "2222",
        ],
        env=os.environ,
    )
    print("it ran ... something?")
    await deferLater(reactor, 1, lambda: None)
    print("terminating")
    accept.signalProcess(signal.SIGTERM)

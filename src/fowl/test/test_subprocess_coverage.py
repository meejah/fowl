import os
import sys
import signal
from twisted.internet.task import deferLater
from twisted.internet.protocol import ProcessProtocol, Protocol, Factory
import pytest_twisted


@pytest_twisted.ensureDeferred
async def test_foo(reactor):
    accept_proto = ProcessProtocol()
    accept = reactor.spawnProcess(
        accept_proto,
        sys.executable,
        [
            "python", "-u", "-m", "fowl.cli",
            "--mailbox", "ws://localhost:4000/v1",
            "--allow-listen", "2222",
        ],
        env=os.environ,
    )
    print("it ran ... something?")
    await deferLater(reactor, 2.8, lambda: None)
    print("terminating")
    accept.signalProcess(signal.SIGTERM)

import sys
import time
import json
import os
from io import (
    BytesIO,
    StringIO,
)
from os.path import exists, join
from functools import partial

import attr

from twisted.internet.defer import (
    returnValue,
    Deferred,
    maybeDeferred,
)
from twisted.internet.task import (
    deferLater,
)
from twisted.internet.protocol import (
    ProcessProtocol,
)
from twisted.internet.error import (
    ProcessExitedAlready,
    ProcessDone,
)
import pytest_twisted


class _MagicTextProtocol(ProcessProtocol):
    """
    Internal helper.

    Monitors all stdout looking for a magic string, and then
    .callback()s on self.done and .errback's if the process exits
    """

    def __init__(self, magic_text, log_function):
        self.magic_seen = Deferred()
        self.exited = Deferred()
        self._magic_text = magic_text
        self._output = StringIO()
        self._log_function = log_function

    def processEnded(self, reason):
        if self.magic_seen is not None:
            d, self.magic_seen = self.magic_seen, None
            d.errback(Exception("Service failed."))
        self.exited.callback(None)

    def childDataReceived(self, childFD, data):
        if childFD == 1:
            self.out_received(data)
        elif childFD == 2:
            self.err_received(data)
        else:
            ProcessProtocol.childDataReceived(self, childFD, data)

    def out_received(self, data):
        """
        Called with output from stdout.
        """
        self._output.write(data.decode("utf8"))
        if self._log_function:
            self._log_function(data.decode("utf8"))
        if self.magic_seen is not None and self._magic_text in self._output.getvalue():
            print("Saw '{}' in the logs".format(self._magic_text))
            d, self.magic_seen = self.magic_seen, None
            d.callback(self)

    def err_received(self, data):
        """
        Output on stderr
        """
        sys.stdout.write(data.decode("utf8"))


def run_service(
    reactor,
    request,
    magic_text,
    executable,
    args,
    cwd=None,
    log_collector=print,
):
    """
    Start a service, and capture the output from the service

    This will start the service, and the returned deferred will fire with
    the process, once the given magic text is seeen.

    :param reactor: The reactor to use to launch the process.
    :param request: The pytest request object to use for cleanup.
    :param magic_text: Text to look for in the logs, that indicate the service
        is ready to accept requests.
    :param executable: The executable to run.
    :param args: The arguments to pass to the process.
    :param cwd: The working directory of the process.

    :return Deferred[IProcessTransport]: The started process.
    """
    protocol = _MagicTextProtocol(magic_text, log_collector)

    env = os.environ.copy()
    env['PYTHONUNBUFFERED'] = '1'
    process = reactor.spawnProcess(
        protocol,
        executable,
        args,
        path=cwd,
        # Twisted on Windows doesn't support customizing FDs
        childFDs={0: 'w', 1: 'r', 2: 'r',} if sys.platform != "win32" else None,
        env=env,
    )
    request.addfinalizer(partial(_cleanup_service_process, process, protocol.exited))
    return protocol.magic_seen.addCallback(lambda ignored: process)


def _cleanup_service_process(process, exited):
    """
    Terminate the given process with a kill signal (SIGKILL on POSIX,
    TerminateProcess on Windows).

    :param process: The `IProcessTransport` representing the process.
    :param exited: A `Deferred` which fires when the process has exited.

    :return: After the process has exited.
    """
    try:
        if process.pid is not None:
            print("signaling {} with TERM".format(process.pid))
            process.signalProcess('TERM')
            print("signaled, blocking on exit")
            pytest_twisted.blockon(exited)
        print("exited, goodbye")
    except ProcessExitedAlready:
        pass


@attr.s
class WormholeMailboxServer:
    """
    A locally-running Magic Wormhole mailbox server
    """
    reactor = attr.ib()
    process_transport = attr.ib()
    url = attr.ib()
    logs = attr.ib()

    @classmethod
    async def create(cls, reactor, request):
        args = [
            sys.executable,
            "-m",
            "twisted",
            "wormhole-mailbox",
            # note, this tied to "url" below
            "--port", "tcp:4000:interface=localhost",
        ]
        logs = list()
        transport = await run_service(
            reactor,
            request,
            magic_text="Starting reactor...",
            executable=sys.executable,
            args=args,
            log_collector=lambda d: logs.append(d),
        )
        # XXX some sort of cleanup
        #request.addfinalizer(partial(_cleanup_service_process, transport, protocol.exited, ctx))
        return cls(
            reactor,
            transport,
            "ws://localhost:4000/v1",
            logs,
        )

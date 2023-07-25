import os
import sys
import attr
from functools import partial
from io import StringIO

import pytest_twisted

from twisted.internet.protocol import ProcessProtocol
from twisted.internet.error import ProcessExitedAlready, ProcessDone
from twisted.internet.defer import Deferred


class _MagicTextProtocol(ProcessProtocol):
    """
    Internal helper. Monitors all stdout looking for a magic string,
    and then .callback()s on self.done or .errback's if the process exits
    """

    def __init__(self, magic_text, print_logs=True):
        self.magic_seen = Deferred()
        self.exited = Deferred()
        self._magic_text = magic_text
        self._output = StringIO()
        self._print_logs = print_logs
        self._stdout_listeners = []

    def add_stdout_listener(self, listener):
        self._stdout_listeners.append(listener)

    def processEnded(self, reason):
        if self.magic_seen is not None:
            d, self.magic_seen = self.magic_seen, None
            d.errback(Exception("Service failed."))
        self.exited.callback(None)

    def childDataReceived(self, childFD, data):
        if childFD == 1:
            self.out_received(data)
            for x in self._stdout_listeners:
                x.stdout_received(data)
        elif childFD == 2:
            self.err_received(data)
        else:
            ProcessProtocol.childDataReceived(self, childFD, data)

    def out_received(self, data):
        """
        Called with output from stdout.
        """
        if self._print_logs:
            sys.stdout.write(data.decode("utf8"))
        self._output.write(data.decode("utf8"))
        if self.magic_seen is not None and self._magic_text in self._output.getvalue():
            # print("Saw '{}' in the logs".format(self._magic_text))
            d, self.magic_seen = self.magic_seen, None
            d.callback(self)

    def err_received(self, data):
        """
        Called when non-JSON lines are received on stderr.
        """
        sys.stdout.write(data.decode("utf8"))


def run_service(
    reactor,
    request,
    executable,
    args,
    magic_text=None,
    cwd=None,
    print_logs=True,
    protocol=None,
):
    """
    Start a service, and capture the output from the service.

    This will start the service.

    The returned deferred will fire (with the IProcessTransport for
    the child) once the given magic text is seeen.

    :param reactor: The reactor to use to launch the process.
    :param request: The pytest request object to use for cleanup.
    :param magic_text: Text to look for in the logs, that indicate the service
        is ready to accept requests.
    :param executable: The executable to run.
    :param args: The arguments to pass to the process.
    :param cwd: The working directory of the process.

    :return Deferred[IProcessTransport]: The started process.
    """
    if protocol is None:
        protocol = _MagicTextProtocol(magic_text, print_logs=print_logs)
        saw_magic = protocol.magic_seen
    else:
        saw_magic = Deferred()
        saw_magic.callback(None)

    env = os.environ.copy()
    env['PYTHONUNBUFFERED'] = '1'
    process = reactor.spawnProcess(
        protocol,
        executable,
        args,
        path=cwd,
        env=env,
    )
    request.addfinalizer(partial(_cleanup_service_process, process, protocol.exited))
    return saw_magic.addCallback(lambda ignored: process)


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
            # print(f"signaling {process.pid} with TERM")
            process.signalProcess('TERM')
            # print("signaled, blocking on exit")
            pytest_twisted.blockon(exited)
    except ProcessExitedAlready:
        pass


@attr.s
class WormholeMailboxServer:
    """
    A locally-running Magic Wormhole mailbox server (on port 4000)
    """
    reactor = attr.ib()
    process_transport = attr.ib()
    url = attr.ib()

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
        transport = await run_service(
            reactor,
            request,
            executable=sys.executable,
            args=args,
            magic_text="Starting reactor...",
            print_logs=False,  # twisted json struct-log
        )
        return cls(
            reactor,
            transport,
            url="ws://localhost:4000/v1",
        )

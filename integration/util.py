import os
import sys
import attr
import json
from collections import defaultdict
from functools import partial
from io import StringIO

from attr import define

import pytest_twisted

from twisted.internet.interfaces import ITransport
from twisted.internet.protocol import ProcessProtocol
from twisted.internet.error import ProcessExitedAlready
from twisted.internet.defer import Deferred

from fowl._proto import parse_fowld_output


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
    :param args: The arguments to pass following "python -m ...", approximately.
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
    # if we're not running tests while we have "coverage" installed,
    # are we even alive? (that is: not coverage here is not optional)
    # shout-out to Ned Batchelder for this tool!
    realargs = [sys.executable, "-m", "coverage", "run", "--parallel", "-m"] + args
    process = reactor.spawnProcess(
        protocol,
        sys.executable,
        realargs,
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
            "twisted",
            "wormhole-mailbox",
            # note, this tied to "url" below
            "--port", "tcp:4000:interface=localhost",
        ]
        transport = await run_service(
            reactor,
            request,
            args=args,
            magic_text="Starting reactor...",
            print_logs=False,  # twisted json struct-log
        )
        return cls(
            reactor,
            transport,
            url="ws://localhost:4000/v1",
        )


@define
class _Fowl:
    transport: ITransport
    protocol: ProcessProtocol


class _FowlProtocol(ProcessProtocol):
    """
    This speaks to an underlying ``fowl`` sub-process.
    """

    def __init__(self):
        # all messages we've received that _haven't_ yet been asked
        # for via next_message()
        self._messages = []
        # maps str -> list[Deferred]: kind-string to awaiters
        self._message_awaits = defaultdict(list)
        self.exited = Deferred()
        self._data = b""

    def processEnded(self, reason):
        self.exited.callback(None)

    def childDataReceived(self, childFD, data):
        if childFD != 1:
            print(data.decode("utf8"), end="")
            return

        self._data += data
        while b'\n' in self._data:
            line, self._data = self._data.split(b"\n", 1)
            try:
                msg, _timestamp = parse_fowld_output(line)
            except Exception as e:
                print(f"Not JSON: {line}: {e}")
            else:
                self._maybe_notify(msg)

    def _maybe_notify(self, msg):
        type_ = type(msg)
        if type_ in self._message_awaits:
            notify, self._message_awaits[type_] = self._message_awaits[type_], list()
            for d in notify:
                d.callback(msg)
        else:
            self._messages.append(msg)

    def send_message(self, js):
        data = json.dumps(js).encode("utf8") + b"\n"
        self.transport.write(data)

    def next_message(self, klass):
        d = Deferred()
        for idx, msg in enumerate(self._messages):
            if isinstance(msg, klass):
                del self._messages[idx]
                d.callback(msg)
                return d
        self._message_awaits[klass].append(d)
        return d

    def all_messages(self, klass=None):
        # we _do_ want to make a copy of the list every time
        # (so the caller can't "accidentally" mess with our state)
        return [
            msg
            for msg in self._messages
            if klass is None or isinstance(msg, klass)
        ]


async def fowld(reactor, request, *extra_args, mailbox=None):
    """
    Run `fowl` with a given subcommand
    """

    # note: running "python -m fowl" is same as "fowld" helper
    args = [
        "fowl",
    ]
    if mailbox is not None:
        args.extend([
            "--mailbox", mailbox,
        ])
    args.extend(extra_args)
    proto = _FowlProtocol()
    transport = await run_service(
        reactor,
        request,
        args=args,
        protocol=proto,
    )
    return _Fowl(transport, proto)

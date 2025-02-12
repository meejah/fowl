import os
import sys
import json
from collections import defaultdict

from twisted.internet.defer import Deferred
from twisted.internet.task import react
from twisted.internet.protocol import ProcessProtocol, Protocol, Factory
from twisted.internet.endpoints import serverFromString, clientFromString

from fowl.observer import Next, Accumulate


class _FowlProtocol(ProcessProtocol):
    """
    This speaks to an underlying ``fow`` sub-process.
    ``fow`` consumes and emits a line-oriented JSON protocol.
    """

    def __init__(self):
        # all messages we've received that _haven't_ yet been asked
        # for via next_message()
        self._messages = []
        # maps str -> list[Deferred]: kind-string to awaiters
        self._message_awaits = defaultdict(list)
        self.exited = Deferred()

    def processEnded(self, reason):
        self.exited.callback(None)

    def childDataReceived(self, childFD, data):
        try:
            js = json.loads(data)
        except Exception:
            print("BAD", data.decode("utf8"))
        else:
            self._maybe_notify(js)

    def _maybe_notify(self, js):
        kind = js["kind"]
        if kind in self._message_awaits:
            notify, self._message_awaits[kind] = self._message_awaits[kind], list()
            for d in notify:
                d.callback(js)
        else:
            self._messages.append(js)
            print(js)

    def send_message(self, msg):
        data = json.dumps(msg)
        self.transport.write(data.encode("utf8") + b"\n")

    def next_message(self, kind):
        d = Deferred()
        for idx, msg in enumerate(self._messages):
            if kind == msg["kind"]:
                del self._messages[idx]
                d.callback(msg)
                return d
        self._message_awaits[kind].append(d)
        return d

    def all_messages(self, kind=None):
        # we _do_ want to make a copy of the list every time
        # (so the caller can't "accidentally" mess with our state)
        return [
            msg
            for msg in self._messages
            if kind is None or msg["kind"] == kind
        ]


@react
async def main(reactor):
    host_proto = _FowlProtocol()
    reactor.spawnProcess(
        host_proto,
        sys.executable,
        [sys.executable, "-m", "fowl", "--mailbox", "ws://127.0.0.1:4000/v1"],
        env={"PYTHONUNBUFFERED": "1"},
    )
    host_proto.send_message({"kind": "allocate-code"})
    msg = await host_proto.next_message("code-allocated")

    guest_proto = _FowlProtocol()
    reactor.spawnProcess(
        guest_proto,
        sys.executable,
        [sys.executable, "-m", "fowl", "--mailbox", "ws://127.0.0.1:4000/v1"],
        env={"PYTHONUNBUFFERED": "1"},
    )
    guest_proto.send_message({"kind": "set-code", "code": msg["code"]})
    msg = await guest_proto.next_message("code-allocated")

    print("waiting for peers")
    await host_proto.next_message("peer-connected")
    print("one peer")
    await guest_proto.next_message("peer-connected")
    print("two peers")

    if 'remote' in sys.argv:
        guest_proto.send_message({
            "kind": "grant-permission",
            "connect": [1111],
            "listen": [],  ## this is annoying, fix in fowld
        })
        host_proto.send_message({
            "kind": "local",
            "listen": "tcp:8888:interface=127.0.0.1",
            "connect": "tcp:127.0.0.1:1111",
        })

        m = await host_proto.next_message("listening")
    else:
        print("local forward")
        guest_proto.send_message({
            "kind": "grant-permission",
            "connect": [],  # FIXME annoying
            "listen": [8888],
        })
        host_proto.send_message({
            "kind": "grant-permission",
            "connect": [1111],
            "listen": [],  ## this is annoying, fix in fowld
        })
        host_proto.send_message({
            "kind": "remote",
            "listen": "tcp:8888:interface=127.0.0.1",
            "connect": "tcp:127.0.0.1:1111"
        })
        m = await guest_proto.next_message("listening")
    print("got it", m)


    class Server(Protocol):
        _message = Accumulate(b"")

        def dataReceived(self, data):
            self._message.some_results(reactor, data)

        async def next_message(self, expected_size):
            return await self._message.next_item(reactor, expected_size)

        def send(self, data):
            self.transport.write(data)


    class Client(Protocol):
        _message = Accumulate(b"")

        def dataReceived(self, data):
            self._message.some_results(reactor, data)

        async def next_message(self, expected_size):
            return await self._message.next_item(reactor, expected_size)

        def send(self, data):
            self.transport.write(data)


    class ServerFactory(Factory):
        protocol = Server
        noisy = True
        _got_protocol = Next()

        async def next_client(self):
            return await self._got_protocol.next_item()

        def buildProtocol(self, *args):
            p = super().buildProtocol(*args)
            self._got_protocol.trigger(reactor, p)
            return p

    listener = ServerFactory()
    server_port = await serverFromString(reactor, "tcp:1111:interface=127.0.0.1").listen(listener)

    # if we do 'too many' test-cases debian complains about
    # "twisted.internet.error.ConnectBindError: Couldn't bind: 24: Too
    # many open files."
    # gc.collect() doesn't fix it.
    who = True
    for size in range(2**6, 2**18, 2**10):
        print("TEST", size, who)
        client = clientFromString(reactor, "tcp:127.0.0.1:8888")
        client_proto = await client.connect(Factory.forProtocol(Client))
        server = await listener.next_client()

        data = os.urandom(size)
        if who:
            client_proto.send(data)
            msg = await server.next_message(len(data))
        else:
            server.send(data)
            msg = await client_proto.next_message(len(data))
        who = not who
        assert msg == data, "Incorrect data transfer"

    print(host_proto.all_messages())
    print(guest_proto.all_messages())

    guest_proto.transport.signalProcess('TERM')
    host_proto.transport.signalProcess('TERM')

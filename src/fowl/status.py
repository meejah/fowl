import time
import json
import random
import functools
from typing import Dict, Optional, Callable

import humanize


from fowl.messages import BytesIn, BytesOut, OutgoingConnection, OutgoingDone, OutgoingLost, Listening, Welcome, PeerConnected, LocalListener, RemoteListeningSucceeded, WormholeClosed, CodeAllocated, IncomingConnection, IncomingDone, IncomingLost

import attrs


@attrs.define
class Subchannel:
    endpoint: str
    i: list
    o: list


@attrs.define
class Listener:
    listen: str
    connect: str
    remote: bool

from .messages import FowlOutputMessage

@attrs.define
class FowlStatus:
    url: Optional[str] = None
    welcome: dict = {}
    code: Optional[str] = None
    verifier: Optional[str] = None
    closed: Optional[str] = None  # closed status, "happy", "lonely" etc
    subchannels: Dict[str, Subchannel] = {}
    listeners: Dict[str, Listener] = {}
    time_provider: Callable[[], float] = time.time
    on_message: Optional[Callable[[FowlOutputMessage], None]] = None

    def __attrs_post_init__(self):
        @functools.singledispatch
        def on_message(msg):
            print(f"unhandled: {msg}")

        @on_message.register(Welcome)
        def _(msg):
            self.url = msg.url
            self.welcome = msg.welcome
            self.closed = None

        @on_message.register(CodeAllocated)
        def _(msg):
            self.code = msg.code

        @on_message.register(PeerConnected)
        def _(msg):
            self.verifier = msg.verifier

        @on_message.register(WormholeClosed)
        def _(msg):
            self.closed = msg.result

        @on_message.register(Listening)
        def _(msg):
            self.listeners[msg.listener_id] = Listener(msg.listen, msg.connect, False)

        @on_message.register(RemoteListeningSucceeded)
        def _(msg):
            self.listeners[msg.listener_id] = Listener(msg.listen, msg.connect, True)

        @on_message.register(BytesIn)
        def _(msg):
            self.subchannels[msg.id].i.insert(0, (msg.bytes, self.time_provider()))

        @on_message.register(BytesOut)
        def _(msg):
            self.subchannels[msg.id].o.insert(0, (msg.bytes, self.time_provider()))

        @on_message.register(IncomingConnection)
        def _(msg):
            self.subchannels[msg.id] = Subchannel(msg.endpoint, [], [])

        @on_message.register(IncomingDone)
        def _(msg):
            #out = humanize.naturalsize(sum([b for b, _ in subchannels[msg.id].o]))
            #in_ = humanize.naturalsize(sum([b for b, _ in subchannels[msg.id].i]))
            #print(f"{msg.id} closed: {out} out, {in_} in")
            del self.subchannels[msg.id]

        @on_message.register(IncomingLost)
        def _(msg):
            del self.subchannels[msg.id]

        @on_message.register(OutgoingConnection)
        def _(msg):
            self.subchannels[msg.id] = Subchannel(msg.endpoint, [], [])

        @on_message.register(OutgoingDone)
        def _(msg):
            #out = humanize.naturalsize(sum([b for b, _ in subchannels[msg.id].o]))
            #in_ = humanize.naturalsize(sum([b for b, _ in subchannels[msg.id].i]))
            #print(f"{msg.id} closed: {out} out, {in_} in")
            del self.subchannels[msg.id]

        @on_message.register(OutgoingLost)
        def _(msg):
            del self.subchannels[msg.id]

        self.on_message = on_message

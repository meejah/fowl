import time
import json
from typing import Dict, Optional, Callable

import attrs

from wormhole._status import Connected, Connecting, ConnectedPeer, NoCode, ConsumedCode, Disconnected, Failed, Closed
from wormhole import DilationStatus, WormholeStatus

from fowl.messages import BytesIn, BytesOut, OutgoingConnection, OutgoingDone, OutgoingLost, Listening, Welcome, PeerConnected, WormholeClosed, CodeAllocated, IncomingConnection, IncomingDone, IncomingLost, GotMessageFromPeer, FowlOutputMessage, WormholeError, AwaitingConnect


@attrs.define
class Subchannel:
    service_name: str
    channel_id: str
    i: list
    o: list
    done_at: Optional[int] = None # timestamp when ended, or None


@attrs.define
class Listener:
    service_name: str
    local_port: int
    remote: bool
    remote_port: Optional[int] = None


@attrs.frozen
class FowlStatus:
    url: Optional[str] = None
    welcome: dict = {}
    code: Optional[str] = None
    verifier: Optional[str] = None
    closed: Optional[str] = None  # closed status, "happy", "lonely" etc
    peer_connected: Optional[str] = None  # hint-description if connected
    subchannels: Dict[str, Subchannel] = attrs.Factory(dict)
    listeners: Dict[str, Listener] = attrs.Factory(dict)
    peer_closing: bool = False
    we_closing: bool = False
    is_connecting: bool = False
    hints: list = attrs.Factory(list)
    lost: list = attrs.Factory(list)  # 3-tuples: (time, channel_id, reason-string)


@attrs.define
class _StatusTracker:
    """
    Internal helper. Tracks current status and listeners and contains
    tools for updating the current status.
    """

    _time_provider: Callable[[], float] = time.time
    _listeners: list = attrs.Factory(list)  # receives FowlOutputMessage instances
    _on_status_updates: list = attrs.Factory(list)
    _current_status: FowlStatus = attrs.Factory(FowlStatus)

    def add_status_listener(self, listener: Callable[[FowlStatus], None]):
        """
        Add a listener function which receives the new FowlStatus every
        time it is updated
        """
        self._on_status_updates.append(listener)

    def add_listener(self, listener: Callable[[FowlOutputMessage], None]):
        """
        Add a listeners which receives FowlOutputMessage instances
        (basically 'incremental' updates)
        """
        self._listeners.append(listener)

    def _emit(self, msg):
        for target in self._listeners:
            target(msg)

    def _modify_status(self, **kwargs):
        status = attrs.evolve(self._current_status, **kwargs)
        self._current_status = status
        self._notify_listeners()

    def _notify_listeners(self):
        for target in self._on_status_updates:
            target(self._current_status)

    @property
    def current_status(self):
        return self._current_status

    def wormhole_status(self, st: WormholeStatus):
        """
        Hooked into our wormhole.
        """
        ##print(st)
        kwargs = self._convert_wormhole_status(st)
        self._modify_status(**kwargs)
        # anything we care about from status should be wired through as a
        # FowlOutputMessage or so externally.

    def _convert_wormhole_status(self, st: WormholeStatus) -> dict:
        kwargs = dict()
        if isinstance(st.mailbox_connection, Connected):
            kwargs["url"] = st.mailbox_connection.url
            kwargs["is_connecting"] = False
        elif isinstance(st.mailbox_connection, Connecting):
            kwargs["url"] = st.mailbox_connection.url
            kwargs["is_connecting"] = True
        elif isinstance(st.mailbox_connection, (Disconnected, Failed, Closed)):
            kwargs["url"] = None
            kwargs["is_connecting"] = False

        if st.code == NoCode() or st.code == ConsumedCode() :
            kwargs["code"] = None
        # actual code comes from .get_code()
        return kwargs

    def dilation_status(self, st: DilationStatus):
        """
        Hooked into our wormhole.
        """
        ##print(st)
        self.wormhole_status(st.mailbox)
        kwargs = dict()
        if isinstance(st.peer_connection, ConnectedPeer):
            kwargs["peer_connected"] = st.peer_connection.hint_description
        else:
            kwargs["peer_connected"] = None

        kwargs["hints"] = [
            "{} {}".format("🐣" if h.is_direct else "🥚", h.url)
            for h in st.hints
        ]
        self._modify_status(**kwargs)

    def welcomed(self, welcome):
        self._modify_status(
            welcome=welcome,
            closed=None
        )
        self._emit(Welcome(self._current_status.url, welcome))

    def code_allocated(self, code):
        self._modify_status(code=code)
        self._emit(CodeAllocated(code))

    def peer_connected(self, verifier, features):
        self._modify_status(verifier=verifier)
        self._emit(PeerConnected(verifier, features))

    def message_from_peer(self, message):
        # XXX fixme todo can we just get rid of this hole message_to/from_peer via status entirely?
        d = json.loads(message)
        if "closing" in d:
            self._modify_status(peer_closing=True)
        self._emit(GotMessageFromPeer(message))

    def wormhole_closed(self, result):
        self._modify_status(closed=result)
        self._emit(WormholeClosed(result))

    def error(self, message):
        self._emit(
            WormholeError(message)
        )

    def added_local_service(self, name, listen_port, remote_connect_port):
        self._current_status.listeners[name] = Listener(name, listen_port, False, remote_connect_port)
        self._modify_status()
        self._emit(AwaitingConnect(name, listen_port))

    def added_remote_service(self, name, local_connect_port):
        self._current_status.listeners[name] = Listener(name, local_connect_port, True)
        self._modify_status()
        self._emit(Listening(name, local_connect_port))

# channel-id is randomly/etc assigned
# each channel-id is associated with precisely one 'service' (formerly "listener-id")
    def bytes_in(self, channel_id, num):
        self._current_status.subchannels[channel_id].i.insert(0, (num, self._time_provider()))
        self._notify_listeners()
        self._emit(BytesIn(channel_id, num))

    def bytes_out(self, channel_id, num):
        self._current_status.subchannels[channel_id].o.insert(0, (num, self._time_provider()))
        self._notify_listeners()
        self._emit(BytesOut(channel_id, num))

    def incoming_connection(self, service_name, channel_id):
        self._current_status.subchannels[channel_id] = Subchannel(service_name, channel_id, [], [])
        self._notify_listeners()
        self._emit(IncomingConnection(service_name, channel_id))

    def incoming_done(self, channel_id):
        #out = humanize.naturalsize(sum([b for b, _ in subchannels[msg.id].o]))
        #in_ = humanize.naturalsize(sum([b for b, _ in subchannels[msg.id].i]))
        #print(f"{msg.id} closed: {out} out, {in_} in")
        del self._current_status.subchannels[channel_id]
        self._notify_listeners()
        self._emit(IncomingDone(channel_id))

    def incoming_lost(self, channel_id, reason):
        del self._current_status.subchannels[channel_id]
        self._current_status.lost.append((self._time_provider(), channel_id, reason))
        self._notify_listeners()
        self._emit(IncomingLost(channel_id, reason))

    def outgoing_connection(self, service_id, channel_id):
        self._current_status.subchannels[channel_id] = Subchannel(service_id, channel_id, [], [])
        self._notify_listeners()
        self._emit(OutgoingConnection(service_id, channel_id))

    def outgoing_done(self, channel_id):
        # if there was an "other side initiated" error (e.g. "can't connect") then
        #P we get both an "outgoing_lost()" and then an "outgoing_done()"...
        try:
            # todo: periodically flush old channels?
            self._current_status.subchannels[channel_id].done_at = self._time_provider()
            ##del self._current_status.subchannels[channel_id]
        except KeyError:
            pass
        else:
            self._notify_listeners()
            self._emit(OutgoingDone(channel_id))

    def outgoing_lost(self, channel_id, reason):
        del self._current_status.subchannels[channel_id]
        self._current_status.lost.append((self._time_provider(), channel_id, reason))
        self._notify_listeners()
        self._emit(OutgoingLost(channel_id, reason))

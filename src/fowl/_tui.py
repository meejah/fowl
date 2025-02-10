import json
import curses
import textwrap
import functools
from typing import Optional
from base64 import b16encode  # for ping/pong
from os import urandom

import humanize

from twisted.internet.task import deferLater
from twisted.internet.defer import ensureDeferred, race
from twisted.internet.stdio import StandardIO
from twisted.protocols.basic import LineReceiver

from wormhole.errors import LonelyError

import attr

from .observer import Next, When
from ._proto import wormhole_from_config, FowlDaemon, FowlWormhole, fowld_output_to_json
from .messages import (
    Welcome,
    CodeAllocated,
    PeerConnected,
    WormholeClosed,
    AllocateCode,
    SetCode,
    LocalListener,
    RemoteListener,
    Listening,
    RemoteListeningSucceeded,
    BytesIn,
    BytesOut,
    IncomingConnection,
    IncomingDone,
    IncomingLost,
    OutgoingConnection,
    OutgoingDone,
    WormholeError,
    GrantPermission,
    Ping,
    Pong,
)


@attr.frozen
class Connection:
    i: int = 0
    o: int = 0
    listener_id: str = None  # Maybe<str>; Nothing if incoming connection


@attr.frozen
class State:
    code: Optional[str] = None
    connected: bool = False
    verifier: Optional[str] = None
    listeners: list = attr.Factory(list)
    remote_listeners: list = attr.Factory(list)
    connections: dict[int, Connection] = attr.Factory(dict)

    @property
    def pretty_verifier(self):
        # space-ify this, for easier reading
        return " ".join(
            self.verifier[a:a+4]
            for a in range(0, len(self.verifier), 4)
        )


async def frontend_tui(reactor, config):
    print(f"Connecting: {config.relay_url}")

    @functools.singledispatch
    def output_message(msg):
        print(f"\b\b\b\bunhandled output: {msg}")

    @output_message.register(Pong)
    def _(msg):
        print(f"\b\b\b  <- Pong({b16encode(msg.ping_id).decode('utf8')}): {msg.time_of_flight}s\n>>> ", end="")

    @output_message.register(WormholeError)
    def _(msg):
        print(f"\b\b\b\bERROR: {msg.message}")

    @output_message.register(Listening)
    def _(msg):
        print(f"\b\b\b\bListening: {msg.listen}")
        replace_state(attr.evolve(state[0], listeners=state[0].listeners + [msg]))

    @output_message.register(RemoteListeningSucceeded)
    def _(msg):
        print(f"\b\b\b\bRemote side is listening: {msg.listen}")
        replace_state(attr.evolve(state[0], remote_listeners=state[0].remote_listeners + [msg]))

    @output_message.register(IncomingConnection)
    def _(msg):
        conn = state[0].connections
        conn[msg.id] = Connection(0, 0, msg.listener_id)
        replace_state(attr.evolve(state[0], connections=conn))

    @output_message.register(IncomingDone)
    def _(msg):
        print(f"\b\b\b\bClosed: {msg.id}")
        conn = state[0].connections
        del conn[msg.id]
        replace_state(attr.evolve(state[0], connections=conn))

    @output_message.register(IncomingLost)
    def _(msg):
        print(f"\b\b\b\bLost: {msg.id}: {msg.reason}")
        conn = state[0].connections
        del conn[msg.id]
        replace_state(attr.evolve(state[0], connections=conn))

    @output_message.register(OutgoingConnection)
    def _(msg):
        conn = state[0].connections
        conn[msg.id] = Connection(0, 0, msg.listener_id)
        replace_state(attr.evolve(state[0], connections=conn))

    @output_message.register(OutgoingDone)
    def _(msg):
        conn = state[0].connections
        print(f"\b\b\b\bClosed: {msg.id} from {conn[msg.id].listener_id}")
        del conn[msg.id]
        replace_state(attr.evolve(state[0], connections=conn))

    @output_message.register(BytesIn)
    def _(msg):
        conn = state[0].connections
        conn[msg.id] = attr.evolve(conn[msg.id], i=conn[msg.id].i + msg.bytes)
        replace_state(attr.evolve(state[0], connections=conn))

    @output_message.register(BytesOut)
    def _(msg):
        conn = state[0].connections
        conn[msg.id] = attr.evolve(conn[msg.id], o=conn[msg.id].o + msg.bytes)
        replace_state(attr.evolve(state[0], connections=conn))

    @output_message.register(WormholeClosed)
    def _(msg):
        print(f"{msg.result}...", end="", flush=True)

    @output_message.register(Welcome)
    def _(msg):
        print("\b\b\b\b", end="")
        print("Connected.")
        if "motd" in msg.welcome:
            print(textwrap.fill(msg.welcome["motd"].strip(), 80, initial_indent="    ", subsequent_indent="    "))
        print(">>> ", end="", flush=True)

    start_time = reactor.seconds()

    if config.output_debug_messages:
        def output_wrapper(msg):
            try:
                js = fowld_output_to_json(msg)
                # don't leak our absolute time, more convenient anyway
                js["timestamp"] = reactor.seconds() - start_time
                config.output_debug_messages.write(
                    json.dumps(js) + "\n"
                )
            except Exception as e:
                print(e)
            return output_message(msg)
    else:
        output_wrapper = output_message

    daemon = FowlDaemon(reactor, config, output_wrapper)
    w = await wormhole_from_config(reactor, config)
    wh = FowlWormhole(reactor, w, daemon, config)

    # make into IService?
    wh.start()

    state = [State()]

    def replace_state(new_state):
        ##print("replace with", new_state)
        ##print(state[0])
        old = state[0]
        new_output = "\b\b\b\b"
        if new_state.connected and not old.connected:
            new_output += "Connected to peer!\n"
        if new_state.code and old.code is None:
            new_output += "Code: {}\n".format(new_state.code)
        if new_state.verifier and old.verifier is None:
            new_output += "Verifier: {}\n".format(new_state.pretty_verifier)
        for conid, conn in new_state.connections.items():
            b = conn.i + conn.o
            if b:
                new_output += f"{conid}: {humanize.naturalsize(b)}\n"
        if new_output:
            print(f"{new_output}>>> ", end="", flush=True)
        state[0] = new_state

    @output_message.register(CodeAllocated)
    def _(msg):
        replace_state(attr.evolve(state[0], code=msg.code))

    @output_message.register(PeerConnected)
    def _(msg):
        replace_state(attr.evolve(state[0], connected=True, verifier=msg.verifier))

    create_stdio = config.create_stdio or StandardIO
    command_reader = CommandReader(reactor)
    create_stdio(command_reader)

    print(">>> ", end="", flush=True)
    while True:
        wc = ensureDeferred(command_reader.when_closed())
        what, result = await race([
            ensureDeferred(command_reader.next_command()),
            wc,
        ])
        if what == 0:
            cmd_line = result
            if cmd_line.strip():
                cmd = cmd_line.decode("utf8").split()
                cmd_name = cmd[0]
                try:
                    cmd_fn = commands[cmd_name]
                except KeyError:
                    if cmd_name.strip().lower() == "quit" or cmd_name.strip().lower() == "q":
                        break
                    print(f'No such command "{cmd_name}"')
                    print("Commands: {}".format(" ".join(commands.keys())))
                    print("Ctrl-d to quit")
                    print(">>> ", end="", flush=True)
                    continue
                # XXX should be passing "high level" FowlWormhole thing, not Wormhole direct
                await cmd_fn(reactor, wh, state[0], *cmd[1:])
            else:
                print(">>> ", end="", flush=True)
        elif what == 1:
            break

    print("\nClosing mailbox...", end="", flush=True)
    try:
        await w.close()
    except LonelyError:
        pass
    print("done.")


async def _cmd_help(reactor, wh, state, *args):
    """
    Some helpful words
    """
    funs = dict()
    for name, fn in commands.items():
        try:
            funs[fn].append(name)
        except KeyError:
            funs[fn] = [name]
    for fn, aliases in funs.items():
        name = sorted(aliases)[-1]
        rest = " ".join(sorted(aliases)[:-1])
        helptext = textwrap.dedent(fn.__doc__)
        if helptext:
            print(f"{name} ({rest})")
            print(textwrap.fill(helptext.strip(), 80, initial_indent="    ", subsequent_indent="    "))
            print()


async def _cmd_invite(reactor, wh, state, *args):
    """
    Allocate a code (to give to a peer)
    """
    if args:
        print("No arguments allowed")
        return
    # XXX fixme no private usage
    if state.code is not None:
        print(f"Existing code: {state.code}")
    else:
        wh.command(AllocateCode())


async def _cmd_accept(reactor, wh, state, *args):
    """
    Consume an already-allocated code (from a peer)
    """
    if len(args) != 1:
        print('Require a secret code (e.g. from "invite" on the other side)')
        return
    if state.code is not None:
        print(f"Existing code: {state.code}")
    else:
        wh.command(SetCode(args[0]))


async def _cmd_listen_local(reactor, wh, state, *args):
    """
    Listen locally on the given port; connect to the remote side on
    the same port (or a custom one if two ports are passed)
    """
    try:
        port = int(args[0])
    except (ValueError, IndexError):
        print("Requires a TCP port, as an integer.")
        print("We will listen on this TCP port on localhost, and connect the same")
        print("localhost port on the far side. Optionally, a second port may be")
        print("specified to use a different far-side port")
        return

    if len(args) > 1:
        try:
            remote_port = int(args[1])
        except ValueError:
            print(f"Not port-number: {args[1]}")
            return
    else:
        remote_port = port

    wh.command(
        GrantPermission(
            listen=[port],
            connect=[],
        )
    )
    wh.command(
        LocalListener(
            listen=f"tcp:{port}:interface=localhost",
            connect=f"tcp:localhost:{remote_port}",
        )
    )


async def _cmd_listen_remote(reactor, wh, state, *args):
    """
    Listen on the remote side on the given port; connect back to this
    side on the same port (or a custom one if two ports are passed)
    """
    try:
        remote_port = int(args[0])
    except (ValueError, IndexError):
        print("Requires a TCP port, as an integer.")
        print("We will listen on this TCP port on the remote side and connect to the same")
        print("localhost port on this side. Optionally, a second port may be specified")
        print("to use a different local port")
        return

    if len(args) > 1:
        try:
            local_port = int(args[1])
        except ValueError:
            print(f"Not port-number: {args[1]}")
            return
    else:
        local_port = remote_port

    wh.command(
        GrantPermission(
            listen=[],
            connect=[local_port],
        )
    )
    wh.command(
        RemoteListener(
            listen=f"tcp:{remote_port}:interface=localhost",
            connect=f"tcp:localhost:{local_port}",
        )
    )


async def _cmd_allow(reactor, wh, state, *args):
    """
    Allow an incoming connection on a particular port
    """
    try:
        local_port = int(args[0])
    except (ValueError, IndexError):
        print("Requires a TCP port, as an integer.")
        print("If the other side tries to connect via this port, we will allow it")
        return
    wh.command(
        GrantPermission(
            listen=[],
            connect=[local_port],
        )
    )


async def _cmd_allow_listen(reactor, wh, state, *args):
    """
    Allow remote side to listen on a given TCP port.
    """
    try:
        local_port = int(args[0])
    except (ValueError, IndexError):
        print("Requires a TCP port, as an integer.")
        print("We will allow the other side to listen on this TCP port")
        return
    wh.command(
        GrantPermission(
            listen=[local_port],
            connect=[],
        )
    )


async def _cmd_ping(reactor, wh, state, *args):
    """
    Send a ping (through the Mailbox Server)
    """
    ping_id = None
    if len(args) != 0:
        raise Exception("No argument accepted to ping")
    ping_id = urandom(4)
    print(f"  -> Ping({b16encode(ping_id).decode('utf8')})\n>>> ", end="")
    wh.command(Ping(ping_id))


async def _cmd_status(reactor, wh, state, *args):
    print("status")
    peer = "disconnected"
    if state.connected:
        peer = "yes"
    if state.verifier:
        peer += f" verifier={state.verifier}"
    else:
        print(f"  code: {state.code}")
    print(f"  peer: {peer}")
    if state.listeners:
        print("  listeners:")
        for listener in state.listeners:
            print(f"    {listener.listener_id.lower()}: {listener.listen} -> {listener.connect}")
    if state.remote_listeners:
        print("  remote listeners:")
        for listener in state.remote_listeners:
            print(f"    {listener.listener_id}: {listener.connect} <- {listener.listen}")
    if state.connections:
        print("  connections:")
        for conn_id, conn in state.connections.items():
            listener = ""
            if conn.listener_id is not None:
                listener = f"  (via {conn.listener_id})"
            print(f"    {conn_id}: {conn.i} bytes in / {conn.o} bytes out{listener}")
    print(">>> ", end="", flush=True)


class CommandReader(LineReceiver):
    """
    Wait for incoming commands from the user
    """
    delimiter = b"\n"
    _next_command = None
    _closed = None
    reactor = None

    def __init__(self, reactor):
        super().__init__()
        self.reactor = reactor
        self._next_command = Next()
        self._closed = When()

    async def next_command(self):
        return await self._next_command.next_item()

    async def when_closed(self):
        return await self._closed.when_triggered()

    def connectionMade(self):
        pass

    def lineReceived(self, line):
        self._next_command.trigger(self.reactor, line)

    def connectionLost(self, why):
        # beware: triggering with "why" goes to errback chain, not
        # what we usually want
        self._closed.trigger(self.reactor, None)


## okay, well that is entertaining, but want something quicker to
## facilitate refactoring, so "REPL-style" it'll be for now?
## ...but would be great to expand that to have "status" style
## info "above" the repl stuff, e.g. bandwidth etc
async def curses_frontend_tui(reactor, config):
    w = await wormhole_from_config(config)

    # XXX does "curses.wrapper" work with async functions?
    ##curses.wrapper(partial(_tui, config, w))

    try:
        stdscr = curses.initscr()
        curses.noecho()
        curses.cbreak()
        curses.curs_set(0)
        stdscr.keypad(True)
        stdscr.nodelay(True)  # non-blocking getch()

        await _tui(reactor, config, w, stdscr)

    finally:
        curses.nocbreak()
        stdscr.keypad(False)
        curses.echo()
        curses.endwin()


async def sleep(reactor, delay):
    await deferLater(reactor, delay, lambda: None)


async def _tui(reactor, config, w, stdscr):
    stdscr.clear()

    d0 = w.get_welcome()
    d1 = w.get_code()
    d2 = w.get_versions()

    stdscr.addstr(0, 1, "welcome:")
    stdscr.addstr(1, 4, "code:")
    stdscr.addstr(2, 0, "versions:")
    stdscr.refresh()

    def got_welcome(js):
        stdscr.addstr(0, 1, f"welcome: {js}")
        stdscr.refresh()
        w.allocate_code()
        return js
    d0.addCallback(got_welcome)

    def got_code(code):
        stdscr.addstr(1, 4, f"code: {code}")
        stdscr.refresh()
        return code
    d1.addCallback(got_code)

    def got_versions(versions):
        w.dilate()
        stdscr.addstr(2, 0, f"versions: {versions}")
        stdscr.refresh()
        return versions
    d2.addCallback(got_versions)

    while True:
        # NOTE: it's vital to "wait" or something on the reactor,
        # otherwise we're madly busy-looping in curses (only!) and
        # nothing else can happen
        await sleep(reactor, 0.1)
        k = stdscr.getch()
        if k != curses.ERR:
            if k == ord('q') or k == ord('Q') or k == 27:
                break

    try:
        await w.close()
    except LonelyError:
        pass


commands = {
    "invite": _cmd_invite,
    "i": _cmd_invite,

    "accept": _cmd_accept,
    "a": _cmd_accept,

    "local": _cmd_listen_local,
    "remote": _cmd_listen_remote,

    "allow": _cmd_allow,
    "allow-listen": _cmd_allow_listen,

    "ping": _cmd_ping,
    "p": _cmd_ping,

    "status": _cmd_status,
    "st": _cmd_status,
    "s": _cmd_status,

    "help": _cmd_help,
    "h":_cmd_help,
    "?": _cmd_help,
}

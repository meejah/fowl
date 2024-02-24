
import curses
import textwrap
import binascii
from typing import IO, Callable, Optional

from twisted.internet.task import deferLater
from twisted.internet.defer import ensureDeferred, DeferredList, race, Deferred
from twisted.internet.stdio import StandardIO
from twisted.protocols.basic import LineReceiver

from wormhole.errors import WormholeError, LonelyError

import attr

from .observer import Next, When
from ._proto import wormhole_from_config, FowlDaemon, FowlWormhole
from ._proto import Welcome, CodeAllocated, PeerConnected



@attr.frozen
class State:
    code: Optional[str] = None
    connected: bool = False
    verifier: Optional[str] = None

    @property
    def pretty_verifier(self):
        # space-ify this, for easier reading
        return " ".join(
            self.verifier[a:a+4]
            for a in range(0, len(self.verifier), 4)
        )




async def frontend_tui(reactor, config):
    print(f"Connecting: {config.relay_url}")

    import functools

    got_welcome = When()
    got_code = When()

    @functools.singledispatch
    def output_message(msg):
        print(f"unhandled output: {msg}")

    @output_message.register(Welcome)
    def _(msg):
        print("\b\b\b\b", end="")
        print(f"Connected.")
        if "motd" in msg.welcome:
            print(textwrap.fill(msg.welcome["motd"].strip(), 80, initial_indent="    ", subsequent_indent="    "))
        print(">>> ", end="", flush=True)

    daemon = FowlDaemon(reactor, config, output_message)
    w = await wormhole_from_config(reactor, config)
    wh = FowlWormhole(reactor, w, daemon, config)
    wh.start()
    print(wh)

    state = [State()]

    # XXX aaaaa, should use FowlDaemon instead

    # Hrrrmmm, thinking ahead: maybe DelegatedWormhole is a better
    # move? Since essentially FowlDaemon will "hook up event-handlers"
    # by doing stuff like get_code().addCallback(self.got_code) or
    # similar -- so just have it "be" a delegate and implement
    # wormhole_got_code() etc ... also journaling only works with
    # Delegate I think? (Why?)

    def replace_state(new_state):
        print("replace with", new_state)
        print(state[0])
        old = state[0]
        new_output = ""
        if new_state.connected and not old.connected:
            new_output += "Connected to peer!\n"
        if new_state.code and old.code is None:
            new_output += "Code: {}\n".format(new_state.code)
        if new_state.verifier and old.verifier is None:
            new_output += "Verifier: {}\n".format(new_state.pretty_verifier)
        if new_output:
            print(f"\n{new_output}>>> ", end="", flush=True)
        state[0] = new_state

    @output_message.register(CodeAllocated)
    def _(msg):
        replace_state(attr.evolve(state[0], code=msg.code))

    @output_message.register(PeerConnected)
    def _(msg):
        w.dilate()
        replace_state(attr.evolve(state[0], connected=True, verifier=msg.verifier))

    create_stdio = config.create_stdio or StandardIO
    command_reader = CommandReader(reactor)
    create_stdio(command_reader)

    while True:
        print(">>> ", end="", flush=True)
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
                except KeyError as e:
                    if cmd_name.strip().lower() == "quit" or cmd_name.strip().lower() == "q":
                        break
                    print(f'No such command "{cmd_name}"')
                    print("Commands: {}".format(" ".join(commands.keys())))
                    print("Ctrl-d to quit")
                    continue
                # XXX should be passing "high level" FowlWormhole thing, not Wormhole direct
                await cmd_fn(reactor, wh, state[0], *cmd[1:])
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
        helptext = fn.__doc__
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
        wh._wormhole.allocate_code()


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
        # XXX fixme no private usage
        wh._wormhole.set_code(args[0])


async def _cmd_listen_local(reactor, wh, state, *args):
    pass


async def _cmd_listen_remote(reactor, wh, state, *args):
    pass


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

    "help": _cmd_help,
    "h":_cmd_help,
    "?": _cmd_help,
}

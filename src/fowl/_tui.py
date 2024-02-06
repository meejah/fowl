
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
from ._proto import wormhole_from_config



@attr.frozen
class State:
    code: Optional[str] = None
    connected: bool = False
    verifier: Optional[str] = None

    @property
    def pretty_verifier(self):
        # space-ify this
        hstr = binascii.hexlify(self.verifier).decode("utf8")
        return " ".join(
            hstr[a:a+4]
            for a in range(0, len(hstr), 4)
        )


async def frontend_tui(reactor, config):
    print(f"Connecting: {config.relay_url}")
    w = await wormhole_from_config(reactor, config)
    welcome = await w.get_welcome()
    print(f"Connected.")
    if "motd" in welcome:
        print(textwrap.fill(welcome["motd"].strip(), 80, initial_indent="    ", subsequent_indent="    "))

    commands = {
        "invite": _cmd_invite,
        "accept": _cmd_accept,
    }
    state = [State([])]

    def replace_state(new_state):
        old = state[0]
        new_output = ""
        if new_state.connected and not old.connected:
            new_output += "Connected to peer!\n"
        if new_state.code and not old.code:
            new_output += "Code: {}\n".format(new_state.code)
        if new_state.verifier and not old.verifier:
            new_output += "Verifier: {}\n".format(new_state.pretty_verifier)
        if new_output:
            print(f"\n{new_output}>>> ", end="", flush=True)
        state[0] = new_state

    code_d = w.get_code()
    def got_code(code):
        replace_state(attr.evolve(state[0], code=code))
        return code
    code_d.addCallbacks(got_code, lambda _: None)

    versions_d = w.get_versions()
    def got_versions(versions):
        w.dilate()
        replace_state(attr.evolve(state[0], connected=True))
        return versions
    versions_d.addCallbacks(got_versions, lambda _: None)

    verifier_d = w.get_verifier()
    def got_verifier(verifier):
        replace_state(attr.evolve(state[0], verifier=verifier, connected=True))
        return verifier
    verifier_d.addCallbacks(got_verifier, lambda _: None)

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
                    print(f'No such command "{cmd_name}"')
                    print("Commands: {}".format(" ".join(commands.keys())))
                    continue
                await cmd_fn(reactor, w, state, *cmd[1:])
        elif what == 1:
            print("\nClosing mailbox...", end="", flush=True)
            try:
                await w.close()
            except LonelyError:
                pass
            print("done.")
            break


async def _cmd_invite(reactor, w, state, *args):
    if args:
        print("No arguments allowed")
        return
    w.allocate_code()


async def _cmd_accept(reactor, w, state, *args):
    if len(args) != 1:
        print('Require a secret code (e.g. from "invite" on the other side)')
        return
    w.set_code(args[0])


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

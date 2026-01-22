
import click
import attrs
from typing import Optional
from ipaddress import IPv4Address, IPv6Address
from importlib import resources
from rich.style import Style
from rich.table import Table
from rich.text import Text
from rich.console import Console

from twisted.internet.task import react
from twisted.internet.defer import ensureDeferred

from wormhole.cli.public_relay import (
    RENDEZVOUS_RELAY as PUBLIC_MAILBOX_URL,
)

from ._proto import (
    _Config,
    forward,
    frontend_accept_or_invite,
    WELL_KNOWN_MAILBOXES,
)
from .messages import (
    LocalListener,
    RemoteListener,
)
from ._tui import frontend_tui
from .visual import littlebitspace_big_logo, littlebitspace_word_logo


@click.option(
    "--version",
    flag_value=True,
    help="Output currently running versions as JSON.",
)
@click.option(
    "--ip-privacy/--clearnet",
    default=False,
    help="Enable operation over Tor (default is public Internet)",
)
@click.option(
    "--mailbox",
    default=PUBLIC_MAILBOX_URL,
    help='URL for the mailbox server to use (or "default", "local" or "winden" to use well-known servers)',
    metavar="URL or NAME",
)
@click.option(
    "--debug",
    default=None,
    help="Output wormhole state-machine transitions to the given file",
    type=click.File("w", encoding="utf8"),
)
@click.command()
@click.pass_context
def fowld(ctx, ip_privacy, mailbox, debug, version):
    """
    Forward Over Wormhole, Locally, Daemon

    Low-level daemon to set up and forward streams over Dilated magic
    wormhole connections
    """
    if version:
        import json
        versions = _versions()
        # versions["kind"] = "version"
        print(json.dumps(versions))
        return

    ctx.obj = _Config(
        relay_url=WELL_KNOWN_MAILBOXES.get(mailbox, mailbox),
        use_tor=bool(ip_privacy),
        debug_file=debug,
    )
    def run(reactor):
        return ensureDeferred(
            forward(
                reactor,
                ctx.obj,
            )
        )
    return react(run)


@click.option(
    "--version",
    flag_value=True,
    help="Display the currently running version",
)
@click.option(
    "--debug-messages",
    default=None,
    type=click.File(mode="w", encoding="utf8"),
    help="Save all input/output messages to a file",
)
@click.option(
    "--ip-privacy/--clearnet",
    default=False,
    help="Enable operation over Tor (default is public Internet)",
)
@click.option(
    "--mailbox",
    default=PUBLIC_MAILBOX_URL,
    help='URL for the mailbox server to use (or "default" or "winden" to use well-known servers)',
    metavar="URL or NAME",
)
@click.option(
    "--debug",
    default=None,
    help="Output wormhole state-machine transitions to the given file",
    type=click.File("w", encoding="utf8"),
)
@click.option(
    "--debug-status",
    default=None,
    help="Output the state of FowlStatus (for use with --replay)",
    type=click.File("w", encoding="utf8", ),
)
@click.option(
    "--replay",
    help="Replay a series of events recorded with --debug-status",
    type=click.File("r", encoding="utf8"),
)
#XXX big change, no longer supports https://github.com/meejah/fowl/issues/37
# -> maybe keep these options, and do the 'name'-based ones as a new thing (--daemon-here or --daemon-there)
# -> maybe do name-based still, but also allow interface (for forwarding...so only on the side that does connect)
#
# NOTE also original usage of "--local" was that the 'fake listener' was/is here!
# (maybe alias --daemon-there / --daemon-here to --local / --remote? --daemon-there == --local (old-style usage))
@click.option(
    "--local", "-L",
    "--client",
    multiple=True,
    help=(
        "We will listen locally, forwarding local connections to the other peer."
        "That is, the other peer is running the daemon-style software."
        "The other peer must enable the same service-name."
        "If a \"remote-connect=\" port is specified, the invocation on the other peer must agree."
        "Therefore, it is best to ONLY choose ports on your side, unless the protocol requires otherwise."
        "If you can avoid choosing at all, a random port is assigned -- this is the most likely to succeed."
        "(Run a corresponding --remote with the same service-name on the other peer)"
    ),
    metavar="service-name:[local-listen-port]:[bind=127.0.0.1]:[remote-connect=port]",
)
@click.option(
    "--remote", "-R",
    "--service",
    multiple=True,
    help=(
        "Listen on the other peer, so the server-style software runs here."
        "The other peer must enable the same service-name."
        "Ports must agree."
        "Therefore, it is best to ONLY choose ports on your side, unless the protocol requires otherwise."
        "If you can avoid choosing at all, a random port is assigned -- this is the most likely to succeed."
       "(Run a corresponding --local with the same service-name on the other peer)"
        ),
    metavar="service-name:[local-connect-port][:listen=port][:address=127.0.0.1]",
)
@click.option(
    "--code-length",
    default=2,
    help="Length of the Wormhole code (if we allocate one)",
)
@click.option(
    "--readme", "-r",
    help="Display the full project README",
    is_flag=True,
)
@click.option(
    "--interactive", "-i",
    help="Run in interactive mode, a human-friendly fowld",
    is_flag=True,
)
@click.option(
    "--no-logo", "--logo",
    is_flag=True,
    help="Display the ANSI logo from littlebitspace (or not)",
    default=False,
)
@click.argument("code", required=False)
@click.command()
def fowl(ip_privacy, mailbox, debug, local, remote, code_length, code, readme, interactive, debug_messages, debug_status, replay, version, no_logo):
    """
    Forward Over Wormhole, Locally

    Bi-directional streaming data over secure and durable Dilated
    magic-wormhole connections.

    This frontend is meant for humans -- if you want machine-parsable
    data and commands, use fowld (or 'python -m fowl')

    Fowl turns self-hostable client/server tools into easy-to-use and
    secure peer to peer services. Every service has a unique name.
    For each such service, one peer runs the server-style process (and
    uses the option "--service") while the other peer runs the
    client-style process (using "--client").

    For example, a traditional Web service might look like this:

        laptop: fowl --service web:8080
        desktop: fowl --client web:8080

    The "laptop" computer is the initiator, and allocates a new
    code. The human running the laptop communicates the code
    out-of-band to the human using the desktop computer (this could be
    the same human).

    Only the "name" of the service is required -- but if you need to
    use a particular port (as with a Web example) then it can be
    specified. Otherwise, a random unused port is used.

    In the above example, we could run the actual services:

        laptop: twist web --path ./
        desktop: curl http://localhost:8080/

    Each peer must "opt in" to particular services, and must also
    agree on ports used (if the ports are not randomly allocated).


    We encourge specifying as little information as possible, with the
    minimum viable setup being just the service names. This will
    result in random ports (revealed only to the respective peer in
    their UI):

        fowl --service chat
        fowl --client chat

    This form of invocation has the best chance of succeeding, as
    unused ports are chosen. The first peer still runs listening style
    softare (e.g. 'nc'), but must retrieve the exact port from the
    UI. Similarly, the second peer still runs connect style software
    (e.g. 'telnet localhost') but also finds the exact port from their
    UI. In this way, the peers don't know which port the other side is
    actually listening on.

    (In our Web example we specify ports because different client /
    server ports can fail the 'same-origin' check).
    """

    if version:
        versions = _versions()
        print(f"    fowl: {versions['fowl']}")
        print(f"wormhole: {versions['wormhole']}")
        return

    if replay:
        _replay_visuals(None, replay)
        return

    if readme:
        display_readme()
        return

    local_services = [
        LocalSpecifier.parse(cmd)
        for cmd in local
    ]
    remote_services = [
        RemoteSpecifier.parse(cmd)
        for cmd in remote
    ]

    commands = [
        spec.to_local()
        for spec in local_services
    ] + [
        spec.to_remote()
        for spec in remote_services
    ]

    if not commands and not interactive:
        c = Console()
        with c.capture() as capture:
            c.print(
                Text.from_ansi(
                    littlebitspace_word_logo,
                    style=Style(bgcolor="#002b36"),
                )
            )
        click.echo_via_pager(
            capture.get() +
            fowl.__doc__ +
            "\nYou must specify at least one --service or --client option" +
            "\n\nFor complete option documentation: fowl --help"
        )
        return

    cfg = _Config(
        relay_url=WELL_KNOWN_MAILBOXES.get(mailbox, mailbox),
        use_tor=bool(ip_privacy),
        debug_file=debug,
        code=code,
        code_length=code_length,
        commands=commands,
        output_debug_messages=debug_messages,
        output_status=debug_status,
        no_logo=no_logo,
    )

    if interactive:
        return tui(cfg)

    def run(reactor):
        return ensureDeferred(frontend_accept_or_invite(reactor, cfg))
    return react(run)


def _to_port(arg):
    if arg is None:
        return None  # facility defaults, for Specifier parsers
    arg = int(arg)
    if arg < 1 or arg >= 65536:
        raise click.UsageError(
            "Ports must be an integer from 1 to 65535"
        )
    return arg


@attrs.frozen
class RemoteSpecifier:
    # corresponds to roost()
    name: str
    connect_port: Optional[int] = None
    local_listen_port: Optional[int] = None
    connect_address: Optional[IPv4Address|IPv6Address] = None

    def to_remote(self):
        return RemoteListener(
            self.name,
            self.local_listen_port,
            self.connect_port,
            self.connect_address,
        )

    @staticmethod
    def parse(cmd: str):
        if '[' in cmd or ']' in cmd:
            raise RuntimeError("Have not considered IPv6 parsing yet")

        colons = cmd.count(':')
        if colons > 3:
            raise ValueError(
                f"Too many colons: {colons} > 3"
            )

        if colons == 0:
            return RemoteSpecifier(cmd)

        if colons == 1:
            name, port0 = cmd.split(':')
            return RemoteSpecifier(name, _to_port(port0))

        specs = cmd.split(':')
        name = specs.pop(0)
        port0 = _to_port(specs.pop(0))

        named = {
            "listen": None,
            "address": None,
        }
        for idx, spec in enumerate(specs):
            try:
                n, v = spec.split('=')
            except ValueError:
                hint = ""
                try:
                    v = int(spec)
                    hint = f' (try with "listen={v}")'
                except ValueError:
                    hint = f' (try with "address={spec}")'
                raise click.UsageError(
                        f'"{spec}": keyword arguments need an = symbol{hint}'
                    )
            named[n] = v
            if n not in ["listen", "address"]:
                raise click.UsageError(
                    "--remote specifier accepts listen= or address= only"
                )
        return RemoteSpecifier(
            name, port0,
            local_listen_port=_to_port(named["listen"]),
            connect_address=named["address"],  # should be IPv{4,6}Address
        )


@attrs.frozen
class LocalSpecifier:
    # corresponds to fledge()
    name: str
    local_listen_port: Optional[int] = None
    remote_connect_port: Optional[int] = None
    bind_interface: Optional[IPv4Address | IPv6Address] = None

    def to_local(self):
        return LocalListener(
            self.name,
            self.local_listen_port,
            self.remote_connect_port,
            self.bind_interface,
        )

    @staticmethod
    def parse(cmd: str):
        if '[' in cmd or ']' in cmd:
            raise RuntimeError("Have not considered IPv6 parsing yet")

        colons = cmd.count(':')
        if colons > 3:
            raise ValueError(
                f"Too many colons: {colons} > 3"
            )

        if colons == 0:
            return LocalSpecifier(cmd)

        if colons == 1:
            name, port0 = cmd.split(':')
            return LocalSpecifier(name, _to_port(port0))

        specs = cmd.split(':')
        name = specs.pop(0)
        port0 = _to_port(specs.pop(0))

        named = {
            "remote-connect": None,
            "bind": None,
        }
        for spec in specs:
            n, v = spec.split('=')
            named[n] = v
            if n not in ["remote-connect", "bind"]:
                raise click.UsageError(
                    "--local specifier accepts remote-connect= or bind= only"
                )
        return LocalSpecifier(
            name, port0,
            remote_connect_port=_to_port(named["remote-connect"]),
            bind_interface=named["bind"],  # should be IPv{4,6}Address
        )


Specifier = LocalSpecifier | RemoteSpecifier


def _replay_visuals(cfg, messages):
    """
    Replay a series of events output from --debug-messages

    Such a file consists of one JSON message per line; the timestamp=
    values are honoured, so the playback is real time.
    """
    from rich.live import Live
    from .visual import render_status
    from .status import _StatusTracker, FowlStatus, Listener, Subchannel
    import time
    import json


    with messages as f:
        messages = [
            json.loads(line)
            for line in f.readlines()
        ]
    where_are_we = messages[0]["timestamp"]

    def current_time():
        print(f"current {where_are_we}")
        return where_are_we
    status_tracker = _StatusTracker(time_provider=current_time)

    def render():
        return render_status(status_tracker.current_status, where_are_we)
    from rich.console import Console
    console = Console(force_terminal=True)
    live = Live(get_renderable=render, console=console)

    #if 1:
    with live:
        while messages:
            data = messages.pop(0)
            timestamp = data.pop("timestamp")

            msg = FowlStatus(**data)
            msg = attrs.evolve(
                msg,
                listeners={
                    kw["service_name"]: Listener(**kw)
                    for kw in msg.listeners.values()
                },
                subchannels={
                    kw["channel_id"]: Subchannel(**kw)
                    for kw in msg.subchannels.values()
                },
            )
            print(msg)
            # time is hard
            # intuitively, we want to trigger a redraw 4 times a second
            # ...but waiting 0.25s with time.sleep() isn't right,
            # because we take a non-zero amount of time to do the rest
            # ... and are we doing "wall-clock time" or some kind of
            # virtual shit here, who can say.
            delay = timestamp - where_are_we
            target = time.time() + delay
            while time.time() < target:
                status_tracker._current_status = msg
                amount = min(0.23, max(0.0, target - time.time()))
                where_are_we += amount
                time.sleep(amount)

            # regardless of any overruns, clam to target
            where_are_we = timestamp


def _versions():
    """
    Return information about interesting versions
    """
    from fowl import __version__ as fowl_version
    from wormhole import __version__ as wormhole_version
    return {
        "fowl": fowl_version,
        "wormhole": wormhole_version,
    }


def tui(cfg):
    """
    Run an interactive text user-interface (TUI)

    Allows one to use a human-readable version of the controller
    protocol directly to set up listeners, monitor streams, etc
    """

    def run(reactor):
        return ensureDeferred(frontend_tui(reactor, cfg))
    return react(run)


def display_readme():
    """
    Display the project README
    """
    layout = Table.grid("text", "digram")
    logo = Text.from_ansi(
        littlebitspace_big_logo,
        no_wrap=True,
        style=Style(bgcolor="#002b36"),
    )
    layout.add_row(
        resources.files("fowl").joinpath("README.rst").read_text(encoding="utf8"),
        logo,
    )

    c = Console()
    with c.capture() as capture:
        c.print(layout)
    click.echo_via_pager(capture.get())

if __name__ == "__main__":
    try:
        import coverage
        coverage.process_startup()
    except ImportError:
        pass
    fowl()

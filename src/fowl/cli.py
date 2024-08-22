
import click
import pkg_resources
from attr import evolve

from twisted.internet.task import react
from twisted.internet.defer import ensureDeferred

from wormhole.cli.public_relay import (
    RENDEZVOUS_RELAY as PUBLIC_MAILBOX_URL,
)

from ._proto import (
    _Config,
    wormhole_from_config,
    forward,
    frontend_accept_or_invite,
    WELL_KNOWN_MAILBOXES,
)
from ._tui import frontend_tui
from .messages import (
    LocalListener,
    RemoteListener,
)
from .policy import LocalhostTcpPortsListenPolicy, LocalhostTcpPortsConnectPolicy


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
def fowld(ctx, ip_privacy, mailbox, debug):
    """
    Forward Over Wormhole, Locally, Daemon

    Low-level daemon to set up and forward streams over Dilated magic
    wormhole connections
    """
    ctx.obj = _Config(
        relay_url=WELL_KNOWN_MAILBOXES.get(mailbox, mailbox),
        use_tor=bool(ip_privacy),
        debug_file=debug,
        # these will be empty; client must activate ports by sending
        # messages to allow listening (or connecting)
        listen_policy = LocalhostTcpPortsListenPolicy([]),
        connect_policy = LocalhostTcpPortsConnectPolicy([]),
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
    "--local", "-L",
    multiple=True,
    help="Listen locally, connect remotely (accepted multiple times)",
    metavar="listen-port[:connect-port]",
)
@click.option(
    "--remote", "-R",
    multiple=True,
    help="Listen remotely, connect locally (accepted multiple times)",
    metavar="listen-port[:connect-port]",
)
@click.option(
    "--allow-listen",
    multiple=True,
    help="Accept a connection to this local port. Accepted multiple times. Note that local listeners added via --local are already allowed and do not need this option.",
    metavar="listen-port",
)
@click.option(
    "--allow-connect",
    multiple=True,
    help="Accept a connection to this local port. Accepted multiple times",
    metavar="connect-port",
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
@click.argument("code", required=False)
@click.command()
def fowl(ip_privacy, mailbox, debug, allow_listen, allow_connect, local, remote, code_length, code, readme, interactive):
    """
    Forward Over Wormhole, Locally

    Bi-directional streaming data over secure and durable Dilated
    magic-wormhole connections.

    This frontend is meant for humans -- if you want machine-parsable
    data and commands, use fowld (or 'python -m fowl')

    This will create a new session (allocating a fresh code) by
    default. To join an existing session (e.g. you've been given a
    code) add the code as an (optional) argument on the command-line.
    """
    if readme:
        display_readme()
        return

    def to_command(cls, cmd):
        if ':' in cmd:
            listen, connect = cmd.split(':')
        else:
            listen = connect = cmd
        # XXX ipv6?
        return cls(
            f"tcp:{listen}:interface=localhost",
            f"tcp:localhost:{connect}",
        )

    def to_listener(cmd):
        if ':' in cmd:
            listen, _ = cmd.split(':')
        else:
            listen = cmd
        return int(listen)

    cfg = _Config(
        relay_url=WELL_KNOWN_MAILBOXES.get(mailbox, mailbox),
        use_tor=bool(ip_privacy),
        debug_file=debug,
        code=code,
        code_length=code_length,
        commands=[
            to_command(LocalListener, cmd)
            for cmd in local
        ] + [
            to_command(RemoteListener, cmd)
            for cmd in remote
        ],
        listen_policy = LocalhostTcpPortsListenPolicy([to_listener(cmd) for cmd in local]),
        connect_policy = LocalhostTcpPortsConnectPolicy([int(conn) for conn in allow_connect]),
    )

    if interactive:
        return tui(cfg)

    def run(reactor):
        return ensureDeferred(frontend_accept_or_invite(reactor, cfg))
    return react(run)


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
    readme = pkg_resources.resource_string('fowl', '../../README.rst')
    # uhm, docutils documentation is confusing as all hell and no good
    # examples of "convert this rST string to anything else" .. :/ but
    # we should "render" it to text
    click.echo_via_pager(readme.decode('utf8'))


if __name__ == "__main__":
    fowl()

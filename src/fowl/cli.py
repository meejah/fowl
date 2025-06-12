
import click
import pkg_resources

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
from ._tui import frontend_tui
from .messages import (
    LocalListener,
    RemoteListener,
)
from .policy import (
    LocalhostTcpPortsListenPolicy,
    LocalhostTcpPortsConnectPolicy,
    ArbitraryAddressTcpConnectPolicy,
    ArbitraryInterfaceTcpPortsListenPolicy,
    is_localhost,
)


WOULD_DO_NOTHING_ERROR = """
You have requested no listeners and allowed neither listening nor connecting.
This would not do anything useful.

You should use at least one of: --remote, --local, --allow-listen or --allow-connect
For more information: fowl --help
"""



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
    "--local", "-L",
    multiple=True,
    help=(
        "We will listen locally, so ask the remote peer to forward connections to us."
        "The other peer must enable the same service-name. Ports must agree."
        "Therefore, it is best to ONLY choose ports on your side, unless the protocol requires otherwise."
        "If you can avoid choosing at all, a random port is assigned -- this is the most likely to succeed."
    ),
    metavar="service-name:[local-connect-port]:[remote-listen-port]",
)
@click.option(
    "--remote", "-R",
    multiple=True,
    help=(
        "Permit the other peer to listen, so we will forward connections from here."
        "The other peer must enable the same service-name. Ports must agree."
        "Therefore, it is best to ONLY choose ports on your side, unless the protocol requires otherwise."
        "If you can avoid choosing at all, a random port is assigned -- this is the most likely to succeed."
        ),
    metavar="service-name:[local-listen-port]:[remote-connect-port]",
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
def fowl(ip_privacy, mailbox, debug, local, remote, code_length, code, readme, interactive, debug_messages):
    """
    Forward Over Wormhole, Locally

    Bi-directional streaming data over secure and durable Dilated
    magic-wormhole connections.

    This frontend is meant for humans -- if you want machine-parsable
    data and commands, use fowld (or 'python -m fowl')

    This will create a new session (allocating a fresh code) by
    default. To join an existing session (e.g. you've been given a
    code) add the code as an (optional) argument on the command-line.

    This only forwards named services; if *this* peer uses '--local
    foo' then the other peer must use '--remote foo' and
    vice-versa. Requesting a port must have corresponding 'permission'
    on the other side. For example:

        fowl --local chat:4444:1234

    ...must have a corresponding invocation with the *exact* same ports:

        fowl --remote chat:1234:4444

    Then, the first peer can run its own listening software (e.g. "nc
    -l 4444") and the second peer can run connect-style software
    (e.g. "telnet localhost 1234")

    We encourge specifying as little information as possible, with the
    minimum viable setup being just the service names. This will
    result in random ports (revealed only to the respective peer in
    their UI):

        fowl --local chat
        fowl --remote chat

    This form of invocation has the best chance of succeeding, as
    unused ports are chosen. The first peer still runs listening style
    softare (e.g. 'nc'), but must retrieve the exact port from the
    UI. Similarly, the second peer still runs connect style software
    (e.g. 'telnet localhost') but also finds the exact port from their
    UI. In this way, the peers don't know which port the other side is
    actually listening on.

    Note that this can fail for things like Web servers which include
    the port as part of the URI and the 'same-origin' check.
    """
    if readme:
        display_readme()
        return

    local_services = [
        _specifier_to_tuples(cmd)
        for cmd in local
    ]
    remote_services = [
        _specifier_to_tuples(cmd)
        for cmd in remote
    ]

    commands = [
        RemoteListener(name, listen, connect)
        for name, listen, connect in local_services
    ] + [
        LocalListener(name, listen)
        for name, listen, _ in remote_services
    ]

    if not commands:
        raise click.UsageError(WOULD_DO_NOTHING_ERROR)

    cfg = _Config(
        relay_url=WELL_KNOWN_MAILBOXES.get(mailbox, mailbox),
        use_tor=bool(ip_privacy),
        debug_file=debug,
        code=code,
        code_length=code_length,
        commands=commands,
        output_debug_messages=debug_messages,
    )

    if interactive:
        return tui(cfg)

    def run(reactor):
        return ensureDeferred(frontend_accept_or_invite(reactor, cfg))
    return react(run)


def _to_port(arg):
    arg = int(arg)
    if arg < 1 or arg >= 65536:
        raise click.UsageError(
            "Ports must be an integer from 1 to 65535"
        )
    return arg


# XXX FIXME use an @frozen attr, not tuple for returns
def _specifier_to_tuples(cmd):
    """
    Parse a local or remote listen/connect specifiers.

    This always returns a 3-tuple of:
      - service name
      - local port (maybe None)
      - remote port (maybe None)
    """
    if '[' in cmd or ']' in cmd:
        raise RuntimeError("Have not considered IPv6 parsing yet")

    colons = cmd.count(':')
    if colons > 2:
        raise ValueError(
            f"Too many colons: {colons} > 2"
        )
    # we use "port0" and "port1" here because whether it's local /
    # remote and listen or connect depends on whether this was --local
    # or --remote originally -- i.e. only the caller knows
    if colons == 2:
        name, port0, port1 = cmd.split(':')
        port0 = _to_port(port0)
        port1 = _to_port(port1)
    elif colons == 1:
        name, port0 = cmd.split(':')
        port0 = _to_port(port0)
        port1 = None
    elif colons == 0:
        name = cmd.strip()
        port0 = port1 = None

    # XXX ipv6?
    return (name, port0, port1)


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
    try:
        import coverage
        coverage.process_startup()
    except ImportError:
        pass
    fowl()

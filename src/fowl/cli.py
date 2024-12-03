
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
    help=(
        "Listen locally, connect remotely (accepted multiple times)."
        "Unless otherwise specified, (local) bind and (remote) connect addresses are localhost."
        'For example "127.0.0.1:1234:127.0.0.1:22" is the same as "1234:22" effectively.'
    ),
    metavar="[bind-address:]listen-port[:remote-address][:connect-port]",
)
@click.option(
    "--remote", "-R",
    multiple=True,
    help=(
        "Listen remotely, connect locally (accepted multiple times)"
        "Unless otherwise specified, the (remote) bind and (local) connect addresses are localhost."
        'For example "127.0.0.1:1234:127.0.0.1:22" is the same as "1234:22" effectively.'
        ),
    metavar="[remote-bind-address:]listen-port[:local-connect-address][:local-connect-port]",
)
@click.option(
    "--allow-listen",
    multiple=True,
    help=(
        "Accept a connection to this local port. Accepted multiple times."
        "Note that local listeners added via --local are already allowed and do not need this option."
        'If no interface is specified, "localhost" is assumed.'
    ),
    metavar="[interface:]listen-port",
)
@click.option(
    "--allow-connect",
    multiple=True,
    help=(
        "Accept a connection to this local port. Accepted multiple times"
        'If no address is specified, "localhost" is assumed.'
    ),
    metavar="[address:]connect-port",
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

    local_commands = [
        _specifier_to_tuples(cmd)
        for cmd in local
    ]
    remote_commands = [
        _specifier_to_tuples(cmd)
        for cmd in remote
    ]

    def to_local(local_interface, local_port, remote_address, remote_port):
        return LocalListener(
            f"tcp:{local_port}:interface={local_interface}",
            f"tcp:{remote_address}:{remote_port}",
        )

    def to_remote(local_interface, local_port, remote_address, remote_port):
        return RemoteListener(
            f"tcp:{local_port}:interface={local_interface}",
            f"tcp:{remote_address}:{remote_port}",
        )

    def to_listen_policy(local_interface, local_port, remote_address, remote_port):
        return local_port

    def to_connect_policy(local_interface, local_port, remote_address, remote_port):
        return remote_port

    def to_iface_port(allowed):
        if ':' in allowed:
            iface, port = allowed.split(':', 1)
            return iface, _to_port(port)
        return "localhost", _to_port(allowed)

    def to_local_port(allowed):
        if ':' in allowed:
            iface, port = allowed.split(':', 1)
            if iface != "localhost":
                raise ValueError(f"Non-local interface: {iface}")
            return _to_port(port)
        return _to_port(allowed)

    def is_local(local_interface, local_port, remote_address, remote_port):
        return is_localhost(local_interface)

    def is_local_connect(local_interface, local_port, remote_address, remote_port):
        return is_localhost(remote_address)

    if any(not is_local(*cmd) for cmd in local_commands) or \
       any(not is_localhost(to_iface_port(allowed)[0]) for allowed in allow_listen):
        listen_policy = ArbitraryInterfaceTcpPortsListenPolicy(
            [(iface, port) for iface, port, _, _ in local_commands] + \
            [to_iface_port(allowed) for allowed in allow_listen]
        )
    else:
        listen_policy = LocalhostTcpPortsListenPolicy(
            [to_listen_policy(*cmd) for cmd in local_commands] +
            [to_local_port(port) for port in allow_listen]
        )

    if any(not is_local_connect(*cmd) for cmd in remote_commands) or \
       any(not is_localhost(to_iface_port(allowed)[0]) for allowed in allow_connect):
        # yes, this says "to_iface_port()" below but they both look
        # the same currently: "192.168.1.2:4321" for example
        connect_policy = ArbitraryAddressTcpConnectPolicy(
            [(addr, port) for _, _, addr, port in remote_commands] + \
            [to_iface_port(allowed) for allowed in allow_connect]
        )
    else:
        connect_policy = LocalhostTcpPortsConnectPolicy(
            [to_connect_policy(*cmd) for cmd in local_commands] +
            [to_local_port(port) for port in allow_connect]
        )

    cfg = _Config(
        relay_url=WELL_KNOWN_MAILBOXES.get(mailbox, mailbox),
        use_tor=bool(ip_privacy),
        debug_file=debug,
        code=code,
        code_length=code_length,
        commands=[
            to_local(*t)
            for t in local_commands
        ] + [
            to_remote(*t)
            for t in remote_commands
        ],
        listen_policy=listen_policy,
        connect_policy=connect_policy,
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

    This always returns a 4-tuple of:
      - listen interface
      - listen port
      - connect address
      - connect port

    TODO: tests, and IPv6
    """
    if '[' in cmd or ']' in cmd:
        raise RuntimeError("Have not considered IPv6 parsing yet")

    colons = cmd.count(':')
    if colons > 3:
        raise ValueError(
            f"Too many colons: {colons} > 3"
        )
    if colons == 3:
        # everything is specified
        listen_interface, listen_port, connect_address, connect_port = cmd.split(':')
        listen_port = _to_port(listen_port)
        connect_port = _to_port(connect_port)
    elif colons == 2:
        # one of the interface / address is specified, but we're not
        # sure which yet
        a, b, c = cmd.split(':')
        try:
            # maybe the first thing is a port
            listen_port = _to_port(a)
            listen_interface = "localhost"
            connect_address = b
            connect_port = _to_port(c)
        except ValueError:
            # no, the first thing is a string, so the connect address
            # must be missing
            listen_interface = a
            listen_port = _to_port(b)
            connect_address = "localhost"
            connect_port = _to_port(c)
    elif colons == 1:
        # we only have one split. this could be "interface:port" or "port:port"
        a, b = cmd.split(':')
        try:
            listen_port = _to_port(a)
            listen_interface = "localhost"
            try:
                # the second thing could be a connect address or a
                # port
                connect_port = _to_port(b)
                connect_address = "localhost"
            except ValueError:
                connect_address = b
                connect_port = listen_port
        except ValueError:
            # okay, first thing isn't a port so it's the listen interface
            listen_interface = a
            listen_port = connect_port = _to_port(b)
            connect_address = "localhost"
    else:
        # no colons, it's a port and we're "symmetric"
        listen_port = connect_port = _to_port(cmd)
        listen_interface = "localhost"
        connect_address = "localhost"

    # XXX ipv6?
    return (
        listen_interface, listen_port,
        connect_address, connect_port,
    )


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


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
    frontend_invite,
    frontend_accept,
)


# XXX need to replicate a bunch of "wormhole *" args?
# e.g. tor stuff, mailbox url, ..

@click.option(
    "--ip-privacy/--clearnet",
    default=False,
    help="Enable operation over Tor (default is public Internet)",
)
@click.option(
    "--mailbox",
    default=PUBLIC_MAILBOX_URL,
    help="URL for the mailbox server to use",
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
    Forward Over Wormhole Daemon

    Low-level daemon to set up and forward streams over Dilated magic
    wormhole connections
    """
    ctx.obj = _Config(
        relay_url=mailbox,
        use_tor=bool(ip_privacy),
        debug_file=debug,
    )
    def run(reactor):
        return ensureDeferred(
            forward(
                ctx.obj,
                wormhole_from_config(ctx.obj),  # coroutine
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
    help="URL for the mailbox server to use",
)
@click.option(
    "--debug",
    default=None,
    help="Output wormhole state-machine transitions to the given file",
    type=click.File("w", encoding="utf8"),
)
@click.group()
@click.pass_context
def fowl(ctx, ip_privacy, mailbox, debug):
    """
    Forward Over Wormhole, Locally

    Bi-directional streaming data over secure and durable Dilated
    magic-wormhole connections.
    """
    ctx.obj = _Config(
        relay_url=mailbox,
        use_tor=bool(ip_privacy),
        debug_file=debug,
    )


@fowl.command()
@click.pass_context
@click.option(
    "--code-length",
    default=2,
    help="Length of the Wormhole code",
)
def invite(ctx, code_length):
    """
    Start a new forwarding session, allocating a code that can be used
    on another computer to join a forwarding session
    """
    ctx.obj = evolve(ctx.obj, code_length=code_length)
    def run(reactor):
        return ensureDeferred(
            frontend_invite(
                ctx.obj,
                wormhole_from_config(ctx.obj),  # coroutine
            )
        )
    return react(run)


@fowl.command()
@click.pass_context
@click.argument("code")
def accept(ctx, code):
    """
    Join a forwarding session by consuming a wormhole code usually
    created by 'fow invite'
    """
    ctx.obj = evolve(ctx.obj, code=code)
    def run(reactor):
        return ensureDeferred(frontend_accept(ctx.obj, wormhole_from_config(ctx.obj)))
    return react(run)


@fowl.command()
def readme():
    """
    Display the project README
    """
    readme = pkg_resources.resource_string('fowl', '../../README.rst')
    # uhm, docutils documentation is confusing as all hell and no good
    # examples of "convert this rST string to anything else" .. :/ but
    # we should "render" it to text
    click.echo_via_pager(readme.decode('utf8'))


def _entry_fowl():
    """
    The entry-point from setup.py
    """
    return fowl()


def _entry_fowld():
    """
    The entry-point from setup.py
    """
    return fowld()

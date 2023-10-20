
import click
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
    "-L",
    multiple=True,
)
@click.option(
    "-R",
    multiple=True,
)
@click.group()
@click.pass_context
def fowl(ctx, ip_privacy, mailbox, l, r):
    """
    Forward Over Wormhole

    Bi-directional streaming data over secure and durable Dilated
    magic-wormhole connections.
    """
    ctx.obj = _Config(
        relay_url=mailbox,
        use_tor=bool(ip_privacy),
        initial_commands = {
            'local': l,
            'remote': r,
            }
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
            forward(
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
        return ensureDeferred(forward(ctx.obj, wormhole_from_config(ctx.obj)))
    return react(run)


def _entry():
    return fowl()

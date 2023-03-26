
import click
from attr import evolve

from twisted.internet.task import react
from twisted.internet.defer import ensureDeferred

from wormhole.cli.public_relay import (
    RENDEZVOUS_RELAY as PUBLIC_MAILBOX_URL,
)

from ._proto import (
    _Config,
    create_wormhole,
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
@click.group()
@click.pass_context
def fow(ctx, ip_privacy, mailbox):
    """
    Forward Over Wormhole

    Bi-directional streaming data over secure and durable Dilated
    magic-wormhole connections.
    """
    ctx.obj = _Config(
        relay_url=mailbox,
        use_tor=bool(ip_privacy),
    )


@fow.command()
@click.pass_context
def invite(ctx):
    """
    Start a new forwarding session, allocating a code that can be used
    on another computer to join a forwarding session
    """
    def run(reactor):
        return ensureDeferred(forward(ctx.obj))
    return react(run)


@fow.command()
@click.pass_context
@click.argument("code")
def accept(ctx, code):
    """
    Join a forwarding session by consuming a wormhole code usually
    created by 'fow invite'
    """
    ctx.obj = evolve(ctx.obj, code=code)
    def run(reactor):
        return ensureDeferred(forward(ctx.obj))
    return react(run)


def _entry():
    return fow()

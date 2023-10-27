
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

@click.command()
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
@click.option(
    "--code-length",
    default=2,
    help="Length of the Wormhole code",
)
@click.argument("code", required=False)
@click.pass_context
def fowl(ctx, ip_privacy, mailbox, debug, code_length, code):
    """
    Forward Over Wormhole

    Bi-directional streaming data over secure and durable Dilated
    magic-wormhole connections.
    """
    ctx.obj = _Config(
        relay_url=mailbox,
        use_tor=bool(ip_privacy),
        debug_file=debug,
        code_length=code_length,
        code=code
    )
    def run(reactor):
        return ensureDeferred(
            forward(
                ctx.obj,
                wormhole_from_config(ctx.obj),  # coroutine
            )
        )
    return react(run)


def _entry():
    return fowl()

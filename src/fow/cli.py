import click


# XXX need to replicate a bunch of "wormhole *" args?
# e.g. tor stuff, mailbox url, ..
# 
@click.group()
@click.pass_context
def fow(ctx):
    """
    Forward Over Wormhole

    Bi-directional streaming data over secure and durable Dilated
    magic-wormhole connections.
    """


@fow.command()
@click.pass_context
def invite(ctx):
    """
    Start a new forwarding session, allocating a code that can be used
    on another computer to join a forwarding session
    """


@fow.command()
@click.pass_context
def accept(ctx):
    """
    Join a forwarding session by consuming a wormhole code usually
    created by 'fow invite'
    """


def _entry():
    return fow()

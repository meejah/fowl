import click


@click.group()
@click.pass_context
def fow(ctx):
    """
    Forward Over Wormhole

    Bi-directional streaming data over secure and durable Dilated
    magic-wormhole connections.
    """


def _entry():
    return fow()

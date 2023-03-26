import sys
import pytest_twisted

from util import run_service


async def fow(reactor, request, subcommand, mailbox=None):
    """
    Run `fow` with a given subcommand
    """

    args = [
        sys.executable,
        "-m",
        "fow",
    ]
    if mailbox is not None:
        args.extend([
            "--mailbox", mailbox,
        ])
    args.append(subcommand)
    print(args)
    transport = await run_service(
        reactor,
        request,
        magic_text='"kind": "welcome"',
        executable=sys.executable,
        args=args,
    )
    print(transport)


@pytest_twisted.ensureDeferred
async def test_happy_path(reactor, request, wormhole):
    """
    start a session and end it immediately

    (if this fails, nothing else will succeed)
    """
    print(wormhole)
    await fow(reactor, request, "invite", mailbox=wormhole.url)

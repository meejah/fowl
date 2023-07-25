import random
import string
import json
from io import StringIO

from click.testing import CliRunner
from attr import define

import pytest
import pytest_twisted

from twisted.internet.task import deferLater
from twisted.internet.defer import ensureDeferred, Deferred

from fow.cli import fow
#from fow.cli import accept
from fow.cli import invite
from fow._proto import (
    _Config,
    wormhole_from_config,
)


# XXX ultimately we might want a "TestingWormhole" object or something
# to put into wormhole proper.
# It would be in-memory and hook up all protocols to .. itself?


def create_wormhole_factory():

    def stream_of_valid_codes():
        for number in range(1, 1000):
            code = "{}-{}-{}".format(
                number,
                random.choice(string.ascii_letters),
                random.choice(string.ascii_letters),
            )
            yield code

    wormholes = []
    codes = stream_of_valid_codes()

    async def memory_wormhole(cfg):
        print("memory wormhole", cfg)

        @define
        class Endpoint:
            connects: list = []
            listens: list = []

            async def connect(self, addr):
                print("connect", addr)
                return self.connects.pop(0)

            def listen(self, factory):
                print("listen", factory)
                ear = self.listens.pop(0)
                return ear(factory)

        @define
        class Wormhole:
            code: str = None
            control_ep: Endpoint = Endpoint()
            connect_ep: Endpoint = Endpoint()
            listen_ep: Endpoint = Endpoint()

            async def get_welcome(self):
                return {
                    "testing": "this is a testing wormhole",
                }

            def allocate_code(self, words):
                self.code = next(codes)
                return self.code

            async def get_code(self):
                return self.code

            async def get_unverified_key(self):
                return b"0" * 32

            async def get_verifier(self):
                return b"x" * 32

            def dilate(self):
                return (self.control_ep, self.connect_ep, self.listen_ep)

        w = Wormhole()
        wormholes.append(w)
        return w
    return memory_wormhole


async def sleep(reactor, t):
    await deferLater(reactor, t, lambda: None)


@pytest_twisted.ensureDeferred
async def find_message(reactor, config, kind=None, timeout=10):
    """
    Await a message of particular kind in the stdout of config
    """
    for _ in range(timeout):
        for msg in [json.loads(line) for line in config.stdout.getvalue().split("\n") if line]:
            if msg["kind"] == kind:
                return msg
        await sleep(reactor, 1)
        print(config.stdout.getvalue())
    raise RuntimeError(
        f"Waited {timeout}s for message of kind={kind}"
    )


@pytest_twisted.ensureDeferred
async def test_forward(reactor, mailbox):
    from fow._proto import forward
    in0 = StringIO()
    in1 = StringIO()

    config0 = _Config(
        relay_url=mailbox.url,
        use_tor=False,
        stdin=in0,
        stdout=StringIO(),
    )
    # note: would like to get rid of this ensureDeferred, but it
    # doesn't start "running" the coro until we do this...
    d0 = ensureDeferred(forward(config0, wormhole_from_config(config0), reactor=reactor))

    msg = await find_message(reactor, config0, kind="wormhole-code")
    assert 'code' in msg, "Missing code"

    config1 = _Config(
        relay_url=mailbox.url,
        use_tor=False,
        stdin=in0,
        stdout=StringIO(),
        code=msg["code"],
    )
    d1 = ensureDeferred(forward(config1, wormhole_from_config(config1), reactor=reactor))
    msg = await find_message(reactor, config1, kind="connected")

    # we're connected .. issue a "open listener" to one side

    in0.write('{"error": "foo"}')

    await Deferred()
    #d0.cancel()
    #d1.cancel()

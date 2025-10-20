import pytest
import pytest_twisted
from util import (
    WormholeMailboxServer,
)


@pytest.fixture(scope='session')
def reactor():
    # this is a fixture in case we might want to try different
    # reactors for some reason.
    from twisted.internet import reactor as _reactor
    return _reactor


@pytest_twisted.async_fixture() # XXX #56 in pytest-twisted :( (scope='session')
async def wormhole(reactor, request):
    """
    A local Magic Wormhole mailbox server
    """
    return await WormholeMailboxServer.create(
        reactor,
        request,
    )

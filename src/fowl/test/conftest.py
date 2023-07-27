import pytest
import pytest_twisted

from twisted.internet.defer import ensureDeferred

from .util import WormholeMailboxServer


@pytest.fixture(scope='session')
def reactor():
    # this is a fixture in case we might want to try different
    # reactors for some reason.
    from twisted.internet import reactor as _reactor
    return _reactor


@pytest.fixture(scope='session')
def mailbox(reactor, request):
    """
    A global wormhole mailbox server instance, running on localhost

    It's often considered 'better practice' to test things like this
    without involving 'actual networking', but wormhole doesn't come
    with test tools in that shape so we'll 'suffer' with the pains of
    actual, localhost networking.
    """

    return pytest_twisted.blockon(
        ensureDeferred(
            WormholeMailboxServer.create(
                reactor,
                request,
            )
        )
    )


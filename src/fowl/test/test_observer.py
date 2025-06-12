from twisted.internet.defer import DeferredList, ensureDeferred

import pytest
import pytest_twisted

from ..observer import Next

##from hypothesis import given, assume

@pytest_twisted.ensureDeferred
async def test_pending_next(reactor):
    """
    a Next instance can be triggered multiple times before being asked
    for its values
    """
    # maybe can parametrize better?
    n = Next()

    # an "already triggered" result)
    n.trigger(reactor, 0)

    # ask for 3 results
    fire_d = [
        n.next_item()
        for _ in range(3)
    ]
    # final result
    n.trigger(reactor, 1)

    # we already had 1 result when we asked for the first item
    res = await fire_d[0]
    assert res == 0

    # ...but asked for 2 more before we got the final result
    res = await fire_d[1]
    assert res == 1
    res = await fire_d[2]
    assert res == 1

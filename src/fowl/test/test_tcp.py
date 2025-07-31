from twisted.internet.protocol import Factory
from twisted.internet.endpoints import TCP4ServerEndpoint
import pytest_twisted

from fowl.tcp import allocate_tcp_port


@pytest_twisted.ensureDeferred()
async def test_allocate_port(reactor):
    p = allocate_tcp_port()
    assert isinstance(p, int)
    assert 1 <= p <= 65535
    # the allocation function should release the port before it
    # returns, so it should be possible to listen on it immediately
    ep = TCP4ServerEndpoint(reactor, p, interface="127.0.0.1")
    port = await ep.listen(Factory())
    await port.stopListening()

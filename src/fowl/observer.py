from attr import define, Factory
from twisted.internet.defer import Deferred, succeed


_UNSET = object()


class Framer:
    """
    Takes a stream of bytes and produces 'messages' from them,
    triggering an underlying Next()-style observable.

    Only produces a single message per reactor 'tick'. If there is
    'already' a subsequent message availble, we use a callLater(0,
    ...) to produce it and check further.

    (This is necessary so that something doing an async iteration has
    a chance to "do other work" .. e.g. call .next_message() again
    ... before any more messages are delivered XXX demo of this problem?)
    """

    def __init__(self, reactor): ## just does LineReceiver for now, find_a_frame):
        self._reactor = reactor
        self._data = b""
        self._next = Next()

    def next_message(self):
        """
        :return Awaitable: a new Deferred that fires when a complete,
        as-yet undelivered message has arrived.
        """
        return self._next.next_item()

    def data_received(self, data):
        self._data += data
        self._maybe_deliver_messages()

    def _find_frame(self, data):
        """
        hard-coded to LineReceiver, could make more general

        :returns: 2-tuple of the message and remaining data. if
            "message" is None, there was no complete message yet and
            all data is returned
        """
        if b"\n" in data:
            return data.split(b"\n", 1)
        return (None, data)

    def _maybe_deliver_messages(self):
        msg, self._data = self._find_frame(self._data)
        if msg is not None:
            self._next.trigger(self._reactor, msg.decode("utf8"))
            if self._find_frame(self._data)[0] is not None:
                self._reactor.callLater(0, self._maybe_deliver_messages)


@define
class Next:
    """
    An observerable event that can by async-ly listened for and
    triggered multiple times.

    Used for implementing the a ``next_thing()`` style of method.
    """

    _awaiters: list = Factory(list)
    _unheard_result: object = _UNSET

    def next_item(self):
        """
        :return Awaitable: a new Deferred that fires when this observable
            triggered. This will always be 'in the future' even if we've
            triggered more than zero times already.
        """
        if self._unheard_result is not _UNSET:
            d = succeed(self._unheard_result)
            self._unheard_result = None
        else:
            d = Deferred()
            self._awaiters.append(d)
        return d

    def trigger(self, reactor, result):
        """
        Triggers all current observers and resets them to the empty list.
        """
        listeners, self._awaiters = self._awaiters, []
        if listeners:
            for d in listeners:
                reactor.callLater(0, d.callback, result)
        else:
            self._unheard_result = result


@define
class When:
    """
    An observerable event that can by async-ly listened for and
    triggers exactly once.

    Used for implementing the a ``when_thing()`` style of method.
    """

    _awaiters: list = Factory(list)
    _result: object = _UNSET

    def when_triggered(self):
        """
        :return Awaitable: a new Deferred that fires when this observable
            triggered. This maybe be 'right now' if we already have a result
        """
        if self._result is not _UNSET:
            d = succeed(self._result)
        else:
            d = Deferred()
            self._awaiters.append(d)
        return d

    def trigger(self, reactor, result):
        """
        Triggers all current observers and resets them to the empty list.
        """
        assert self._result is _UNSET, "Can only trigger it once"
        listeners, self._awaiters = self._awaiters, []
        self._result = result
        for d in listeners:
            reactor.callLater(0, d.callback, result)


@define
class Accumulate:
    """
    An observerable event that can by async-ly listened for and
    triggered multiple times, with a per-event 'size' of item to
    collect (as observed via len() calls).

    Used for implementing the a ``next_message(size=123)`` style of method.
    """

    _results: object
    _awaiters: list = Factory(list)

    def next_item(self, reactor, size):
        """
        :return Awaitable: a new Deferred that fires when this observable
            triggered. This will always be 'in the future' even if we've

            triggered more than zero times already.
        """
        d = Deferred()
        self._awaiters.append((size,d))
        self._examine_results(reactor)
        return d

    def some_results(self, reactor, result):
        """
        Append these results. If this gives us enough results to notify
        current listeners, we do.
        """
        self._results += result
        self._examine_results(reactor)

    def _examine_results(self, reactor):
        if not self._awaiters:
            return
        size, d = self._awaiters[0]
        if len(self._results) >= size:
            self._awaiters.pop(0)
            self._results, result = self._results[size:], self._results[:size]
            reactor.callLater(0, d.callback, result)

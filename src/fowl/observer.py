from attr import define, Factory
from twisted.internet.defer import Deferred, succeed


_UNSET = object()


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
            print("waiters", self._awaiters)
        return d

    def trigger(self, reactor, result):
        """
        Triggers all current observers and resets them to the empty list.
        """
        print("TRIGGER", result)
        listeners, self._awaiters = self._awaiters, []
        if listeners:
            for d in listeners:
                reactor.callLater(0, d.callback, result)
        else:
            print("  (unheard)")
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

from attr import define
from twisted.internet.defer import Deferred


@define
class When:
    """
    An observerable event that can by async-ly listened for and
    triggered exactly once.

    Generally useful to implement the "when_something()" pattern in
    Twisted
    """

    _awaiters: list = []
    _result: object = None

    def when_triggered(self):
        """
        :return Awaitable: a new Deferred that fires when this observable
            has fired (which may have already happened).
        """
        d = Deferred()
        if self._awaiters is None:
            d.callback(self._result)
        else:
            self._awaiters.append(d)
        return d

    def trigger(self, result):
        """
        Called at most once, with the result for this observable
        """
        print(f"{self}: trigger: {result}")
        assert self._awaiters is not None, "Observable triggered twice"
        self._result = result
        listeners, self._awaiters = self._awaiters, None
        for d in listeners:
            d.callback(result)


@define
class Next:
    """
    An observerable event that can by async-ly listened for and
    triggered multiple times.

    Used for implementing the a ``next_thing()`` style of method.
    """

    _awaiters: list = []
    _last_result: object = None

    def next_item(self):
        """
        :return Awaitable: a new Deferred that fires when this observable
            triggered. This will always be 'in the future' even if we've
            triggered more than zero times already.
        """
        if self._last_result is not None:
            r, self._last_result = self._last_result, None
            d.callback(r)
        else:
            d = Deferred()
            self._awaiters.append(d)
            return d

    def got_item(self, result):
        """
        Triggers all current observers and resets them to the empty list.
        """
        assert self._awaiters is not None, "Observable triggered twice"
        listeners, self._awaiters = self._awaiters, []
        print("ZZZ", listeners)
        for d in listeners:
            d.callback(result)
        self._last_result = result

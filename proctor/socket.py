from contextlib import contextmanager
from datetime import datetime

import socks


class InstrumentedSocket(socks.socksocket):
    """ A socket that maintains timing info about connection/disconnection. """
    def __init__(self, callback, *args, **kwargs):
        self._callback = callback
        self._called_back = False
        self._error_count = 0
        self._total_time = 0
        socks.socksocket.__init__(self, *args, **kwargs)

    @contextmanager
    def _timer(self):
        start_time = datetime.now()
        try:
            yield
        except:
            self._error_count += 1
            raise
        finally:
            self._total_time += (datetime.now() - start_time).total_seconds()
            self._callback(self._total_time, self._error_count)
            self._called_back = True

    def connect(self, address):
        with self._timer():
            return socks.socksocket.connect(self, address)

    def shutdown(self, how):
        with self._timer():
            return socks.socksocket.shutdown(self, how)

    def close(self):
        with self._timer():
            result = socks.socksocket.close(self)
        if not self._called_back:
            self._callback(self._total_time, self._error_count)
        return result

from contextlib import contextmanager
from datetime import datetime

import socks


class InstrumentedSocket(socks.socksocket):
    """ A socket that maintains timing info about connection/disconnection.

    The timing info will be sent back once to the callback on either socket
    shutdown(), close(), or on any error.

    """
    def __init__(self, callback, *args, **kwargs):
        self._callback = callback
        self._called_back = False
        self._error_count = 0
        self._total_time = 0
        socks.socksocket.__init__(self, *args, **kwargs)

    @contextmanager
    def _timer(self):
        """ Context manager that measures time spent and count errors. """
        def update_timing():
            self._total_time += (datetime.now() - start_time).total_seconds()

        start_time = datetime.now()
        try:
            try:
                yield
            finally:
                update_timing()
        except:
            self._error_count += 1
            self._do_callback()
            raise

    @contextmanager
    def _callback_on_error(self):
        """ Context manager that sends stats to the callback on errors. """
        try:
            yield
        except:
            self._error_count += 1
            self._do_callback()
            raise

    def _do_callback(self):
        """ Communicate back socket connection statistics. """
        if not self._called_back:
            self._callback(self._total_time, self._error_count)
            self._called_back = True

    def connect(self, address):
        with self._timer():
            return socks.socksocket.connect(self, address)

    def connect_ex(self, address):
        with self._timer():
            return socks.socksocket.connect_ex(self, address)

    def send(self, *args, **kwargs):
        with self._callback_on_error():
            return socks.socksocket.send(self, *args, **kwargs)

    def sendall(self, *args, **kwargs):
        with self._callback_on_error():
            return socks.socksocket.sendall(self, *args, **kwargs)

    def sendto(self, *args, **kwargs):
        with self._callback_on_error():
            return socks.socksocket.sendto(self, *args, **kwargs)

    def sendblocking(self, *args, **kwargs):
        with self._callback_on_error():
            return socks.socksocket.sendblocking(self, *args, **kwargs)

    def recv(self, *args, **kwargs):
        with self._callback_on_error():
            return socks.socksocket.recv(self, *args, **kwargs)

    def recvfrom(self, *args, **kwargs):
        with self._callback_on_error():
            return socks.socksocket.recvfrom(self, *args, **kwargs)

    def recvfrom_into(self, *args, **kwargs):
        with self._callback_on_error():
            return socks.socksocket.recvfrom_into(self, *args, **kwargs)

    def recv_into(self, *args, **kwargs):
        with self._callback_on_error():
            return socks.socksocket.recv_into(self, *args, **kwargs)

    def shutdown(self, how):
        with self._timer():
            result = socks.socksocket.shutdown(self, how)
        self._do_callback()
        return result

    def close(self):
        with self._timer():
            result = socks.socksocket.close(self)
        self._do_callback()
        return result

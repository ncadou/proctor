import logging
from threading import Lock
from urlparse import urlparse, urlunparse, ParseResult

from miproxy.proxy import (
    ProxyHandler, RequestInterceptorPlugin,
    ResponseInterceptorPlugin, UnsupportedSchemeException)
from ssl import wrap_socket

log = logging.getLogger(__name__)


class TorProxyHandler(ProxyHandler):
    def __init__(self, tor_instance, *args, **kwargs):
        self.tor_instance = tor_instance
        ProxyHandler.__init__(self, *args, **kwargs)

    def _connect_to_host(self):
        # Get hostname and port to connect to
        if self.is_connect:
            self.hostname, self.port = self.path.split(':')
            log.debug('Connecting to %s:%s' % (self.hostname, self.port))
        else:
            u = urlparse(self.path)
            if u.scheme != 'http':
                raise UnsupportedSchemeException('Unknown scheme %s'
                                                 % repr(u.scheme))
            log.debug('Using %s to fetch %s'
                      % (self.tor_instance.name, self.path))
            self.hostname = u.hostname
            self.port = u.port or 80
            self.path = urlunparse(
                ParseResult(scheme='', netloc='', params=u.params,
                            path=u.path or '/', query=u.query,
                            fragment=u.fragment))

        # Connect to destination
        self._proxy_sock = None
        while self._proxy_sock is None:
            self._proxy_sock = self.tor_instance.create_socket(
                suppress_errors=True)
        self._proxy_sock.settimeout(10)
        self._proxy_sock.connect((self.hostname, int(self.port)))

        # Wrap socket if SSL is required
        if self.is_connect:
            self._proxy_sock = wrap_socket(self._proxy_sock)

    def mitm_request(self, data):
        # Register start time
        return ProxyHandler.mitm_request(self, data)

    def mitm_response(self, data):
        # Register end time and count requests
        # Keep stats and restart tor instance as needed
        return ProxyHandler.mitm_response(self, data)


class DebugInterceptor(RequestInterceptorPlugin, ResponseInterceptorPlugin):
    def do_request(self, data):
        print '>> %s' % repr(data[:100])
        return data

    def do_response(self, data):
        print '<< %s' % repr(data[:100])
        return data


def tor_proxy_handler_factory(tor_swarm):
    """ Return a factory for TorProxyHandlers bound to Tor instances. """
    tor_instances = tor_swarm.instances()
    generator_lock = Lock()  # Synchronize thread access to the generator.

    def factory(*args, **kwargs):
        while True:
            with generator_lock:
                tor_instance = next(tor_instances)
            if tor_instance.connected:
                break
        return TorProxyHandler(tor_instance, *args, **kwargs)

    return factory

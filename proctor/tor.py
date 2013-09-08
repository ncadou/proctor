from itertools import chain, cycle
from os import path
from threading import Event, Lock, Thread

import socks
from desub import desub

from proctor.socket import InstrumentedSocket

import logging
log = logging.getLogger(__name__)


class TorRunner(Thread):
    """ Tor process runner. """
    def __init__(self, name, socks_port, control_port, base_work_dir):
        super(TorRunner, self).__init__()
        self.name = name
        self.socks_port = socks_port
        self.control_port = control_port
        self.base_work_dir = base_work_dir
        self._connected = Event()
        self._stoprequest = Event()
        self._stats_errors = list()
        self._stats_timing = list()
        self._stats_lock = Lock()
        self._stats_window = 200

    @property
    def work_dir(self):
        return path.join(self.base_work_dir, self.name)

    @property
    def pid_file(self):
        return path.join(self.work_dir, 'pid')

    @property
    def connected(self):
        return self._connected.is_set()

    def run(self):
        """ Run the Tor process and respond to events in a loop. """
        args = dict(CookieAuthentication=0, HashedControlPassword='',
                    ControlPort=self.control_port, PidFile=self.pid_file,
                    SocksPort=self.socks_port, DataDirectory=self.work_dir)
        args = map(str, chain(*(('--' + k, v) for k, v in args.iteritems())))
        tor = desub.join(['tor'] + args)
        tor.start()
        log.debug('Started Tor (%s)' % self.name)
        while tor.is_running():
            if self._stoprequest.wait(1):
                tor.stop()
                log.debug('Stopped Tor (%s)' % self.name)
            if not self._connected.is_set():
                if 'Bootstrapped 100%: Done.' in tor.stdout.read():
                    self._connected.set()
                    log.debug('Tor (%s) is connected' % self.name)
        print tor.stdout.read()
        print tor.stderr.read()

    def _register_stats(self, timing, errors):
        """ Maintain connection statistics over time. """
        with self._stats_lock:
            self._stats_errors.append(errors)
            self._stats_timing.append(timing)
            if len(self._stats_errors) > self._stats_window:
                self._stats_errors = self._stats_errors[-self._stats_window:]
            if len(self._stats_timing) > self._stats_window:
                self._stats_timing = self._stats_timing[-self._stats_window:]
            errors = sum(self._stats_errors)
            timing_avg = sum(self._stats_timing) / len(self._stats_timing)
            print '* %s: errors %s, avg time %s in %s data points)' % (
                self.name, errors, timing_avg, len(self._stats_timing))

    def create_socket(self, *args, **kwargs):
        """ Return an InstrumentedSocket that will connect through Tor. """
        if self.connected:
            sock = InstrumentedSocket(self._register_stats, *args, **kwargs)
            args = (socks.PROXY_TYPE_SOCKS4, 'localhost', self.socks_port,
                    True, None, None)  # rdns, username, password
            sock.setproxy(*args)
            return sock
        else:
            raise RuntimeError('Tor (%s) not yet connected.' % self.name)

    def stop(self):
        """ Signal the thread to stop itself. """
        self._stoprequest.set()


class TorSwarm(object):
    """ Manages a number of Tor processes. """
    def __init__(self, base_socks_port, base_control_port, work_dir):
        self.base_socks_port = base_socks_port
        self.base_control_port = base_control_port
        self.work_dir = work_dir
        self._instances = list()

    def instances(self):
        """ Return an infinite generator cycling through Tor instances. """
        for instance in cycle(self._instances):
            yield instance

    def start(self, num_instances):
        """ Start and return the Tor processes. """
        log.info('Starting Tor swarm with %d instances...' % num_instances)
        self._instances = list()
        for i in range(num_instances):
            tor = TorRunner('tor-%d' % i, self.base_socks_port + i,
                            self.base_control_port + i, self.work_dir)
            self._instances.append(tor)
            tor.start()
        return self._instances

    def stop(self):
        """ Stop the Tor processes and wait for their completion. """
        for tor in self._instances:
            tor.stop()
            tor.join()

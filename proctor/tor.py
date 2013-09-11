from datetime import datetime
from itertools import chain, cycle
from os import path
from threading import Event, Lock, Thread
from time import sleep

import socks
from desub import desub

from proctor.socket import InstrumentedSocket

import logging
log = logging.getLogger(__name__)


class TorProcess(Thread):
    """ Runs and manages a Tor process in a thread.

    This class takes care of starting and stopping a Tor process, as well as
    monitoring connection times and the error rate and restarting the process
    when unhealthy.

    """
    def __init__(self, name, socks_port, control_port, base_work_dir,
                 boot_time_max=30, errors_max=10, conn_time_avg_max=2,
                 grace_time=30, sockets_max=None, resurrections_max=10):
        super(TorProcess, self).__init__()
        self.name = name
        self.socks_port = socks_port
        self.control_port = control_port
        self.base_work_dir = base_work_dir
        self.boot_time_max = boot_time_max
        self.errors_max = errors_max
        self.conn_time_avg_max = conn_time_avg_max
        self.grace_time = grace_time
        self.sockets_max = sockets_max
        self.resurrections_max = resurrections_max
        self._connected = Event()
        self._exclusive_access = Lock()
        self._ref_count = 0
        self._ref_count_lock = Lock()
        self._socket_count = 0
        self._socket_count_lock = Lock()
        self._stats_lock = Lock()
        self._stats_window = 200
        self._stoprequest = Event()
        self._terminated = False

    def run(self):
        """ Run and supervise the Tor process. """
        args = dict(CookieAuthentication=0, HashedControlPassword='',
                    ControlPort=self.control_port, PidFile=self.pid_file,
                    SocksPort=self.socks_port, DataDirectory=self.work_dir)
        args = map(str, chain(*(('--' + k, v) for k, v in args.iteritems())))
        tor = desub.join(['tor'] + args)
        self._start(tor)
        resurrections = 0
        while not self._stoprequest.is_set():
            if not tor.is_running():
                if resurrections >= self.resurrections_max:
                    log.error('Resurrected %s %s times, giving up.'
                              % (self.name, resurrections))
                    self._terminated = True
                    break
                resurrections += 1
                self._restart(tor, died=True)
            else:
                log.info('Started %s' % self.name)
            self.monitor(tor)

    def monitor(self, tor):
        """ Make sure Tor starts and stops when appropriate. """
        while tor.is_running():
            # Stop nicely when asked nicely.
            if self._stoprequest.wait(1):
                tor.stop()
                log.debug('Stopped %s' % self.name)
            # Check health and restart when appropriate.
            elif self._connected.is_set():
                errors, timing_avg, samples = self.get_stats()
                too_many_errors = errors > self.errors_max
                too_slow = timing_avg > self.conn_time_avg_max
                max_use_reached = (self.sockets_max
                                   and self._socket_count >= self.sockets_max)
                needs_restart = too_many_errors or too_slow or max_use_reached
                if self.age > self.grace_time and needs_restart:
                    self._restart(tor)
            else:
                out = tor.stdout.read()
                # Check for successful connection.
                if 'Bootstrapped 100%: Done.' in out:
                    self._connected.set()
                    log.info('%s is connected' % self.name)
                    self._start_time = datetime.utcnow()
                else:
                    # Check if initialization takes too long.
                    if self.time_since_boot > self.boot_time_max:
                        self._restart(tor, failed_boot=True)
                    # Check for socket binding failures.
                    else:
                        for port in [self.socks_port, self.control_port]:
                            if 'Could not bind to 127.0.0.1:%s' % port in out:
                                error = ('Could not bind %s to 127.0.0.1:%s'
                                        % (self.name, port))
                                log.warn(error)
                                self._terminated = True
                                break

    def stop(self):
        """ Signal the thread to stop itself. """
        self._stoprequest.set()

    @property
    def work_dir(self):
        return path.join(self.base_work_dir, self.name)

    @property
    def pid_file(self):
        return path.join(self.work_dir, 'pid')

    @property
    def connected(self):
        return self._connected.is_set()

    @property
    def age(self):
        """ Return the number of seconds since the Tor circuit is usable. """
        return (datetime.utcnow() - self._start_time).total_seconds()

    @property
    def terminated(self):
        return self._terminated

    @property
    def time_since_boot(self):
        """ Return the number of seconds since the last Tor process start. """
        return (datetime.utcnow() - self._boot_time).total_seconds()

    def _start(self, tor):
        """ Start a Tor process. """
        with self._stats_lock:
            self._boot_time = datetime.utcnow()
            self._socket_count = 0
            self._stats_errors = list()
            self._stats_timing = list()
        tor.start()

    def _restart(self, tor, failed_boot=False, died=False):
        """ Safely replace a Tor instance with a fresh one. """
        with self._exclusive_access:  # Prevent creating sockets.
            # Wait until all sockets have finished.
            wait_start = datetime.utcnow()
            while self._ref_count > 0:
                if (datetime.utcnow() - wait_start).total_seconds() > 30:
                    log.error('Likely got a ref_count accounting error in %s'
                              % self.name)
                    self._ref_count = 0
                    break
                sleep(1)
            self._connected.clear()
            if failed_boot:
                log.warn('Restarting %s (did not initialize in time)'
                         % self.name)
            elif died:
                log.warn('Resurrected %s' % self.name)
            else:
                errors, timing_avg, samples = self.get_stats()
                log.warn(('Restarting %s '
                          '(errors: %s, avg time: %s, count: %s, age: %s)')
                         % (self.name, errors, timing_avg, self._socket_count,
                            int(self.age)))
            tor.stop()
            self._start(tor)

    def _inc_socket_count(self):
        """ Increment the internal socket counter. """
        with self._socket_count_lock:
            self._socket_count += 1

    def _inc_ref_count(self):
        """ Increment the internal reference counter. """
        with self._ref_count_lock:
            self._ref_count += 1

    def _dec_ref_count(self):
        """ Decrement the internal reference counter. """
        with self._ref_count_lock:
            self._ref_count -= 1

    def _receive_stats(self, timing, errors):
        """ Maintain connection statistics over time. """
        with self._stats_lock:
            self._stats_errors.append(errors)
            self._stats_timing.append(timing)
            if len(self._stats_errors) > self._stats_window:
                self._stats_errors = self._stats_errors[-self._stats_window:]
                self._stats_timing = self._stats_timing[-self._stats_window:]
            # We consider the socket at end of life when it sends the stats.
            self._dec_ref_count()

    def get_stats(self):
        """ Return current statistics. """
        with self._stats_lock:
            samples = len(self._stats_timing)
            errors = sum(self._stats_errors)
            timing_avg = sum(self._stats_timing) / (samples or 1)
            return errors, timing_avg, samples

    def create_socket(self, suppress_errors=False, *args, **kwargs):
        """ Return an InstrumentedSocket that will connect through Tor. """
        if self.connected:
            if not self._exclusive_access.acquire(False):
                return None
            try:
                sock = InstrumentedSocket(self._receive_stats, *args, **kwargs)
                args = (socks.PROXY_TYPE_SOCKS4, 'localhost', self.socks_port,
                        True, None, None)  # rdns, username, password
                sock.setproxy(*args)
                # Keep track of how many sockets are using this Tor instance.
                self._inc_ref_count()
                self._inc_socket_count()
                return sock
            finally:
                self._exclusive_access.release()
        elif suppress_errors:
            sleep(0.1)  # Prevent fast spinning in (the proxy code) caused by
                        # a race condition when Tor restarts.
            return None
        else:
            raise RuntimeError('%s not yet connected.' % self.name)


class TorSwarm(object):
    """ Manages a number of Tor processes. """
    def __init__(self, base_socks_port, base_control_port, work_dir,
                 sockets_max, **kwargs):
        self.base_socks_port = base_socks_port
        self.base_control_port = base_control_port
        self.work_dir = work_dir
        self.sockets_max = sockets_max
        self.kwargs = kwargs
        self._instances = list()

    def instances(self):
        """ Return an infinite generator cycling through Tor instances. """
        for instance in cycle(self._instances):
            if instance.terminated:
                alive = list(i for i in self._instances if not i.terminated)
                if len(alive) == 0:
                    log.critical('No alive Tor instance left. Bailing out.')
                    return
            yield instance

    def start(self, num_instances):
        """ Start and return the Tor processes. """
        log.info('Starting Tor swarm with %d instances...' % num_instances)
        self._instances = list()
        for i in range(num_instances):
            tor = TorProcess('tor-%d' % i, self.base_socks_port + i,
                            self.base_control_port + i, self.work_dir,
                            sockets_max=self.sockets_max, **self.kwargs)
            self._instances.append(tor)
            tor.start()
            sleep(0.1)
        return self._instances

    def stop(self):
        """ Stop the Tor processes and wait for their completion. """
        for tor in self._instances:
            tor.stop()
            tor.join()

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
    """ Runs and manages a Tor process in a thread. """
    def __init__(self, name, socks_port, control_port, base_work_dir,
                 boot_time_max=30, errors_max=10, per_req_time_avg_max=2,
                 grace_time=30):
        super(TorProcess, self).__init__()
        self.name = name
        self.socks_port = socks_port
        self.control_port = control_port
        self.base_work_dir = base_work_dir
        self.boot_time_max = boot_time_max
        self.errors_max = errors_max
        self.per_req_time_avg_max = per_req_time_avg_max
        self.grace_time = grace_time
        self._connected = Event()
        self._exclusive_access = Lock()
        self._ref_count = 0
        self._ref_count_lock = Lock()
        self._stats_lock = Lock()
        self._stats_window = 200
        self._stoprequest = Event()

    def run(self):
        """ Run the Tor process and respond to events in a loop. """
        args = dict(CookieAuthentication=0, HashedControlPassword='',
                    ControlPort=self.control_port, PidFile=self.pid_file,
                    SocksPort=self.socks_port, DataDirectory=self.work_dir)
        args = map(str, chain(*(('--' + k, v) for k, v in args.iteritems())))
        tor = desub.join(['tor'] + args)
        self._start(tor)
        log.debug('Started %s' % self.name)
        while tor.is_running():
            if self._stoprequest.wait(1):
                tor.stop()
                log.debug('Stopped %s' % self.name)
            if self._connected.is_set():
                errors, timing_avg, samples = self.get_stats()
                needs_restart = ((errors > self.errors_max
                                  or timing_avg > self.per_req_time_avg_max)
                                 and self.age > self.grace_time)
                if needs_restart:
                    self._restart(tor)
            else:
                if 'Bootstrapped 100%: Done.' in tor.stdout.read():
                    self._connected.set()
                    log.debug('%s is connected' % self.name)
                    self._start_time = datetime.utcnow()
                elif self.time_since_boot > self.boot_time_max:
                    self._restart(tor, failed_boot=True)
        print tor.stdout.read()
        print tor.stderr.read()

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
    def time_since_boot(self):
        """ Return the number of seconds since the last Tor process start. """
        return (datetime.utcnow() - self._boot_time).total_seconds()

    def _start(self, tor):
        """ Start a Tor process. """
        with self._stats_lock:
            self._boot_time = datetime.utcnow()
            self._stats_errors = list()
            self._stats_timing = list()
        tor.start()

    def _restart(self, tor, failed_boot=False):
        """ Safely replace a Tor instance with a fresh one. """
        with self._exclusive_access:  # Prevent creating sockets.
            # Wait until all sockets have finished.
            wait_start = datetime.utcnow()
            while self._ref_count > 0:
                print ' * waiting', self.name, self._ref_count
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
            else:
                errors, timing_avg, samples = self.get_stats()
                log.warn('Restarting %s (errors: %s, avg time: %s, age: %s)'
                         % (self.name, errors, timing_avg, int(self.age)))
            tor.stop()
            self._start(tor)

    def _inc_ref_count(self):
        """ Increment the internal reference counter. """
        with self._ref_count_lock:
            self._ref_count += 1
            print ' - ', self.name, self._ref_count

    def _dec_ref_count(self):
        """ Decrement the internal reference counter. """
        with self._ref_count_lock:
            self._ref_count -= 1
            print ' - ', self.name, self._ref_count

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
            print '* %s: errors %s, avg time %s in %s data points (age %s)' % (
                self.name, errors, timing_avg, len(self._stats_timing),
                self.age)
            return errors, timing_avg, samples

    def create_socket(self, *args, **kwargs):
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
                return sock
            finally:
                self._exclusive_access.release()
        else:
            raise RuntimeError('%s not yet connected.' % self.name)


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
            tor = TorProcess('tor-%d' % i, self.base_socks_port + i,
                            self.base_control_port + i, self.work_dir)
            self._instances.append(tor)
            tor.start()
            sleep(0.1)
        return self._instances

    def stop(self):
        """ Stop the Tor processes and wait for their completion. """
        for tor in self._instances:
            tor.stop()
            tor.join()

""" An HTTP proxy that routes requests through a number of Tor circuits. """

import logging
import sys
from argparse import ArgumentParser
from shutil import rmtree
from tempfile import mkdtemp
from time import sleep

from miproxy.proxy import AsyncMitmProxy

from proctor.vendor.exit import handle_exit

LOG_FORMAT = '%(asctime)s,%(msecs)03d %(levelname)-5.5s [%(name)s] %(message)s'


def get_args_parser():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument('-d', '--work-dir', help='Working directory')
    parser.add_argument('-p', '--port', type=int, default=8080,
                        help='Proxy server listening port')
    parser.add_argument('-s', '--base-socks-port', type=int, default=19050,
                        help='Base socks port for the Tor processes')
    parser.add_argument('-c', '--base-control-port', type=int, default=18118,
                        help='Base control port for the Tor processes')
    parser.add_argument('-n', '--instances', type=int, default=2,
                        help='Number of Tor processes to launch')
    parser.add_argument('-m', '--max-use', type=int,
                        help='Max number of requests before replacing '
                             'Tor processes')
    parser.add_argument('-t', '--max-conn-time', type=float, default=2,
                        help='Number of Tor processes to launch')
    return parser


def parse_args():
    parser = get_args_parser()
    parser.add_argument('-l', '--loglevel', default='INFO',
                        choices=('CRITICAL', 'ERROR', 'WARN', 'INFO', 'DEBUG'),
                        help='Display messages above this log level')
    return parser.parse_args()


def run_proxy(port, base_socks_port, base_control_port, work_dir,
              num_instances, sockets_max, **kwargs):
    # Imported here so that the logging module could be initialized by another
    # script that would import from the present module. Not sure that's the
    # best way to accomplish this though.
    from .tor import TorSwarm
    from .proxy import tor_proxy_handler_factory

    log = logging.getLogger(__name__)

    proxy = None
    tor_swarm = None

    def kill_handler():
        log.warn('Interrupted, stopping server')
        try:
            if proxy:
                proxy.server_close()
        finally:
            if tor_swarm is not None:
                tor_swarm.stop()

    with handle_exit(kill_handler):
        tor_swarm = TorSwarm(base_socks_port, base_control_port, work_dir,
                             sockets_max, **kwargs)
        tor_instances = tor_swarm.start(num_instances)
        log.debug('Waiting for at least one connected Tor instance...')
        while not [t for t in tor_instances if t.connected]:
            if len(list(i for i in tor_instances if not i.terminated)) == 0:
                log.critical('No alive Tor instance left. Bailing out.')
                sys.exit(1)
            sleep(0.25)
        handler_factory = tor_proxy_handler_factory(tor_swarm)
        proxy = AsyncMitmProxy(server_address=('', port),
                               RequestHandlerClass=handler_factory)
        log.info('Starting proxy server on port %s' % port)
        proxy.serve_forever()


def main():
    args = parse_args()
    work_dir = args.work_dir or mkdtemp()
    logging.basicConfig(level=getattr(logging, args.loglevel),
                        format=LOG_FORMAT)
    try:
        run_proxy(args.port, args.base_socks_port, args.base_control_port,
                  work_dir, args.instances, args.max_use,
                  conn_time_avg_max=args.max_conn_time)
    finally:
        if not args.work_dir:
            rmtree(work_dir)


if __name__ == '__main__':
    main()

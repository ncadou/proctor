""" An HTTP proxy that routes requests through a number of Tor circuits. """

import logging
import sys
from argparse import ArgumentParser
from shutil import rmtree
from tempfile import mkdtemp
from time import sleep

from miproxy.proxy import AsyncMitmProxy

LOG_FORMAT = '%(asctime)s,%(msecs)03d %(levelname)-5.5s [%(name)s] %(message)s'
log = None


def get_args_parser():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument('-d', '--work-dir', help='Working directory')
    parser.add_argument('-p', '--port', type=int, default=8080,
                        help='Proxy server listening port')
    parser.add_argument('-s', '--base-socks-port', type=int, default=9051,
                        help='Base socks port for the Tor processes')
    parser.add_argument('-c', '--base-control-port', type=int, default=8119,
                        help='Base control port for the Tor processes')
    parser.add_argument('-n', '--instances', type=int, default=2,
                        help='Number of Tor processes to launch')
    return parser


def parse_args():
    parser = get_args_parser()
    parser.add_argument('-l', '--loglevel', default='INFO',
                        choices=('CRITICAL', 'ERROR', 'WARN', 'INFO', 'DEBUG'),
                        help='Display messages above this log level')
    return parser.parse_args()


def run_proxy(port, base_socks_port, base_control_port, work_dir,
              num_instances):
    # Imported here so that the logging module could be initialized by another
    # script that would import from the present module. Not sure that's the
    # best way to accomplish this though.
    from .tor import TorSwarm
    from .proxy import tor_proxy_handler_factory

    proxy = None
    if log is None:
        global log
        log = logging.getLogger(__name__)
    try:
        tor_swarm = TorSwarm(base_socks_port, base_control_port, work_dir)
        tor_instances = tor_swarm.start(num_instances)
        log.debug('Waiting for at least one connected Tor instance...')
        while not [t for t in tor_instances if t.connected]:
            sleep(0.25)
        handler_factory = tor_proxy_handler_factory(tor_swarm)
        proxy = AsyncMitmProxy(server_address=('', port),
                               RequestHandlerClass=handler_factory)
        log.info('Starting proxy server on port %s' % port)
        proxy.serve_forever()
    except KeyboardInterrupt:
        if proxy:
            log.warn('Ctrl C - Stopping server')
            proxy.server_close()
        sys.exit(1)
    finally:
        tor_swarm.stop()


def main():
    args = parse_args()
    work_dir = args.work_dir or mkdtemp()
    logging.basicConfig(level=getattr(logging, args.loglevel),
                        format=LOG_FORMAT)
    try:
        run_proxy(args.port, args.base_socks_port, args.base_control_port,
                  work_dir, args.instances)
    finally:
        if not args.work_dir:
            rmtree(work_dir)


if __name__ == '__main__':
    main()

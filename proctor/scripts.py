""" An HTTP proxy that routes requests through a number of Tor circuits. """

import logging
import sys
from argparse import ArgumentParser
from shutil import rmtree
from tempfile import mkdtemp
from time import sleep

from miproxy.proxy import AsyncMitmProxy

from proctor.tor import TorSwarm
from proctor.proxy import tor_proxy_handler_factory

logging.basicConfig(
    level='DEBUG',
    format='%(asctime)s,%(msecs)03d %(levelname)-5.5s [%(name)s] %(message)s')

log = logging.getLogger(__name__)


def parse_args():
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
    return parser.parse_args()


def main():
    args = parse_args()
    work_dir = args.work_dir or mkdtemp()
    proxy = None
    try:
        tor_swarm = TorSwarm(args.base_socks_port, args.base_control_port,
                             work_dir)
        tor_instances = tor_swarm.start(args.instances)
        log.debug('Waiting for at least one connected Tor instance...')
        while not [t for t in tor_instances if t.connected]:
            sleep(0.25)
        handler_factory = tor_proxy_handler_factory(tor_swarm)
        proxy = AsyncMitmProxy(server_address=('', args.port),
                               RequestHandlerClass=handler_factory)
        log.info('Starting proxy server on port %s' % args.port)
        proxy.serve_forever()
    except KeyboardInterrupt:
        if proxy:
            print '\nCtrl C - Stopping server'
            proxy.server_close()
        sys.exit(1)
    finally:
        tor_swarm.stop()
        if not args.work_dir:
            rmtree(work_dir)


if __name__ == '__main__':
    main()

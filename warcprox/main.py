#!/usr/bin/env python
# vim:set sw=4 et:

from __future__ import absolute_import

try:
    import queue
except ImportError:
    import Queue as queue

import logging
import sys
import hashlib
import argparse
import os
import socket

import certauth.certauth

import warcprox.playback
import warcprox.dedup
import warcprox.warcwriter
import warcprox.warcprox
import warcprox.controller

from warcprox.redisdedup import RedisDedupDb

def _build_arg_parser(prog=os.path.basename(sys.argv[0])):
    arg_parser = argparse.ArgumentParser(prog=prog,
            description='warcprox - WARC writing MITM HTTP/S proxy',
            formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    arg_parser.add_argument('-p', '--port', dest='port', default=8000, type=int,
            help='port to listen on')
    arg_parser.add_argument('-b', '--address', dest='address',
            default='localhost', help='address to listen on')
    arg_parser.add_argument('-c', '--cacert', dest='cacert',
            default='./{0}-warcprox-ca.pem'.format(socket.gethostname()),
            help='CA certificate file; if file does not exist, it will be created')
    arg_parser.add_argument('--certs-dir', dest='certs_dir',
            default='./{0}-warcprox-ca'.format(socket.gethostname()),
            help='where to store and load generated certificates')
    arg_parser.add_argument('-d', '--dir', dest='directory',
            default='./warcs', help='where to write warcs')
    arg_parser.add_argument('-z', '--gzip', dest='gzip', action='store_true',
            help='write gzip-compressed warc records')
    arg_parser.add_argument('-t', '--max-threads', dest='max_threads', type=int, default=None,
            help='max number of threads in pool, if not specified, default to unlimited')
    arg_parser.add_argument('-n', '--prefix', dest='prefix',
            default='WARCPROX', help='WARC filename prefix')
    arg_parser.add_argument('-s', '--size', dest='size', type=int,
            default=1000*1000*1000,
            help='WARC file rollover size threshold in bytes')
    arg_parser.add_argument('--rollover-idle-time',
            dest='rollover_idle_time', default=None, type=int,
            help="WARC file rollover idle time threshold in seconds (so that Friday's last open WARC doesn't sit there all weekend waiting for more data)")

    arg_parser.add_argument('--read-buff-size', dest='buff_size', type=int, default=8192,
                            help='size of read buffer from remote')

    arg_parser.add_argument('--timeout', dest='timeout', type=int, default=10,
                            help='timeout for remote connection socket')

    try:
        hash_algos = hashlib.algorithms_guaranteed
    except AttributeError:
        hash_algos = hashlib.algorithms
    arg_parser.add_argument('-g', '--digest-algorithm', dest='digest_algorithm',
            default='sha1', help='digest algorithm, one of {}'.format(', '.join(hash_algos)))
    arg_parser.add_argument('--base32', dest='base32', action='store_true',
            default=False, help='write digests in Base32 instead of hex')
    arg_parser.add_argument('-j', '--dedup-db-file', dest='dedup_db_file',
            default='./warcprox-dedup.db', help='persistent deduplication database file; empty string or /dev/null disables deduplication')
    arg_parser.add_argument('-P', '--playback-port', dest='playback_port',
            default=None, help='port to listen on for instant playback')
    arg_parser.add_argument('--playback-index-db-file', dest='playback_index_db_file',
            default='./warcprox-playback-index.db',
            help='playback index database file (only used if --playback-port is specified)')
    arg_parser.add_argument('--version', action='version',
            version="warcprox {}".format(warcprox.version_str))
    arg_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true')
    arg_parser.add_argument('-q', '--quiet', dest='quiet', action='store_true')

    arg_parser.add_argument('-m', '--multiwarc', action='store_true')

    arg_parser.add_argument('-i', '--in-place', action='store_true')

    # redis dedup
    arg_parser.add_argument('--redis-dedup-url')
    arg_parser.add_argument('--redis-sesh-timeout', type=int, default=0)
    arg_parser.add_argument('--redis-dupe-timeout', type=int, default=300)
    arg_parser.add_argument('--redis-max-sesh-size', type=int, default=0)


    # [--ispartof=warcinfo ispartof]
    # [--description=warcinfo description]
    # [--operator=warcinfo operator]
    # [--httpheader=warcinfo httpheader]

    return arg_parser


def main(argv=sys.argv):
    arg_parser = _build_arg_parser(prog=os.path.basename(argv[0]))
    args = arg_parser.parse_args(args=argv[1:])

    if args.verbose:
        loglevel = logging.DEBUG
    elif args.quiet:
        loglevel = logging.WARNING
    else:
        loglevel = logging.INFO

    logging.basicConfig(stream=sys.stdout, level=loglevel,
            format='%(asctime)s %(process)d %(levelname)s %(threadName)s %(name)s.%(funcName)s(%(filename)s:%(lineno)d) %(message)s')

    try:
        hashlib.new(args.digest_algorithm)
    except Exception as e:
        logging.fatal(e)
        exit(1)

    # redis dedup
    if args.redis_dedup_url:
        dedup_db = RedisDedupDb(args.redis_dedup_url,
                                args.redis_sesh_timeout,
                                args.redis_dupe_timeout,
                                args.redis_max_sesh_size)

    elif args.dedup_db_file in (None, '', '/dev/null'):
        logging.info('deduplication disabled')
        dedup_db = None
    else:
        dedup_db = warcprox.dedup.DedupDb(args.dedup_db_file)

    recorded_url_q = queue.Queue()

    ca_name = 'Warcprox CA on {}'.format(socket.gethostname())[:64]
    ca = certauth.certauth.CertificateAuthority(args.cacert, args.certs_dir,
                                                ca_name=ca_name)

    proxy = warcprox.warcprox.WarcProxy(
            server_address=(args.address, int(args.port)), ca=ca,
            recorded_url_q=recorded_url_q,
            digest_algorithm=args.digest_algorithm,
            max_threads=args.max_threads,
            buff_size=args.buff_size,
            timeout=args.timeout)

    # redis dedup
    if args.redis_dedup_url:
        playback_index_db = dedup_db
        playback_proxy = None
    elif args.playback_port is not None:
        playback_index_db = warcprox.playback.PlaybackIndexDb(args.playback_index_db_file)
        playback_server_address=(args.address, int(args.playback_port))
        playback_proxy = warcprox.playback.PlaybackProxy(server_address=playback_server_address,
                ca=ca, playback_index_db=playback_index_db,
                warcs_dir=args.directory)
    else:
        playback_index_db = None
        playback_proxy = None


    if args.multiwarc:
        warc_writer_class = warcprox.warcwriter.MultiWarcWriter
    else:
        warc_writer_class = warcprox.warcwriter.WarcWriter

    warc_writer = warc_writer_class(directory=args.directory,
            gzip=args.gzip, prefix=args.prefix, port=args.port,
            rollover_size=args.size, base32=args.base32,
            dedup_db=dedup_db, digest_algorithm=args.digest_algorithm,
            playback_index_db=playback_index_db,
            rollover_idle_time=args.rollover_idle_time,
            write_in_place=args.in_place)

    warc_writer_thread = warcprox.warcwriter.WarcWriterThread(
            recorded_url_q=recorded_url_q, warc_writer=warc_writer)

    controller = warcprox.controller.WarcproxController(proxy, warc_writer_thread, warc_writer, playback_proxy)
    controller.run_until_shutdown()


if __name__ == '__main__':
    main()


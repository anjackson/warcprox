#!/usr/bin/env python
# vim:set sw=4 et:
#
"""
WARC writing MITM HTTP/S proxy

See README.rst or https://github.com/internetarchive/warcprox
"""

from __future__ import absolute_import

try:
    import http.server as http_server
except ImportError:
    import BaseHTTPServer as http_server

try:
    import socketserver
except ImportError:
    import SocketServer as socketserver

try:
    import queue
except ImportError:
    import Queue as queue

try:
    import http.client as http_client
except ImportError:
    import httplib as http_client

import logging
import re
import tempfile
import traceback
import hashlib
import json
import socket

from email.utils import parsedate
from datetime import datetime

import concurrent.futures

from certauth.certauth import CertificateAuthority
from warcprox.mitmproxy import MitmProxyHandler

class ProxyingRecorder(object):
    """
    Wraps a socket._fileobject, recording the bytes as they are read,
    calculating digests, and sending them on to the proxy client.
    """

    logger = logging.getLogger("warcprox.warcprox.ProxyingRecorder")

    LINK_RX = re.compile('<([^>]+)>;\s*rel="original"')

    def __init__(self, fp, proxy_dest, digest_algorithm='sha1', path=''):
        self.fp = fp
        # "The file has no name, and will cease to exist when it is closed."
        self.tempfile = tempfile.SpooledTemporaryFile(max_size=512*1024)
        self.digest_algorithm = digest_algorithm
        self.block_digest = hashlib.new(digest_algorithm)
        self.payload_offset = None
        self.payload_digest = None
        self.proxy_dest = proxy_dest
        self._proxy_dest_conn_open = True
        self._prev_hunk_last_two_bytes = b''
        self.len = 0
        self.path = path
        self.memento_datetime = None
        self.memento_link_original = None

    def _update_payload_digest(self, hunk):
        if self.payload_digest is None:
            # convoluted handling of two newlines crossing hunks
            # XXX write tests for this
            if self._prev_hunk_last_two_bytes.endswith(b'\n'):
                if hunk.startswith(b'\n'):
                    self.payload_digest = hashlib.new(self.digest_algorithm)
                    self.payload_digest.update(hunk[1:])
                    self.payload_offset = self.len + 1
                elif hunk.startswith(b'\r\n'):
                    self.payload_digest = hashlib.new(self.digest_algorithm)
                    self.payload_digest.update(hunk[2:])
                    self.payload_offset = self.len + 2
            elif self._prev_hunk_last_two_bytes == b'\n\r':
                if hunk.startswith(b'\n'):
                    self.payload_digest = hashlib.new(self.digest_algorithm)
                    self.payload_digest.update(hunk[1:])
                    self.payload_offset = self.len + 1
            else:
                m = re.search(br'\n\r?\n', hunk)
                if m is not None:
                    self.payload_digest = hashlib.new(self.digest_algorithm)
                    self.payload_digest.update(hunk[m.end():])
                    self.payload_offset = self.len + m.end()

            # if we still haven't found start of payload hold on to these bytes
            if self.payload_digest is None:
                self._prev_hunk_last_two_bytes = hunk[-2:]
        else:
            self.payload_digest.update(hunk)

    def _update(self, hunk):
        self._update_payload_digest(hunk)
        self.block_digest.update(hunk)

        self.tempfile.write(hunk)

        self.len += len(hunk)

        if self._proxy_dest_conn_open:
            try:
                self.proxy_dest.sendall(hunk)
            except BaseException as e:
                self._proxy_dest_conn_open = False
                self.logger.warn('{} sending data to proxy client'.format(e))
                self.logger.info('will continue downloading from remote server without sending to client')
        else:
            self.logger.debug('Still downloading: {0} {1}'.format(self.path, self.len))

    def read(self, size=-1):
        hunk = self.fp.read(size)
        self._update(hunk)
        return hunk

    def readinto(self, b):
        n = self.fp.readinto(b)
        self._update(b[:n])
        return n

    def readline(self, size=-1):
        # XXX depends on implementation details of self.fp.readline(), in
        # particular that it doesn't call self.fp.read()
        hunk = self.fp.readline(size)

        if self.payload_digest is None:
            self._parse_response_header(hunk)

        self._update(hunk)
        return hunk

    def _parse_response_header(self, buff):
        buff = buff.lower()

        if not self.memento_datetime:
            mem = buff.split('memento-datetime: ', 1)
            if len(mem) == 2:
                mem = mem[1].strip()
                self.memento_datetime = datetime(*parsedate(mem)[:6])

        if not self.memento_link_original:
            link = buff.split('link: ')
            if len(link) == 2:
                link = link[1].strip()
                m = self.LINK_RX.search(link)
                if m:
                    self.memento_link_original = m.group(1)


    def close(self):
        return self.fp.close()

    def __len__(self):
        return self.len

    def payload_size(self):
        if self.payload_offset is not None:
            return self.len - self.payload_offset
        else:
            return 0


class ProxyingRecordingHTTPResponse(http_client.HTTPResponse):

    def __init__(self, sock, debuglevel=0, method=None, proxy_dest=None, digest_algorithm='sha1', path=None):
        http_client.HTTPResponse.__init__(self, sock, debuglevel=debuglevel, method=method)

        # Keep around extra reference to self.fp because HTTPResponse sets
        # self.fp=None after it finishes reading, but we still need it
        self.recorder = ProxyingRecorder(self.fp, proxy_dest, digest_algorithm, path)
        self.fp = self.recorder


class WarcProxyHandler(MitmProxyHandler):
    logger = logging.getLogger("warcprox.warcprox.WarcProxyHandler")

    def _proxy_request(self):
        # Build request
        req_str = '{} {} {}\r\n'.format(self.command, self.path, self.request_version)

        warcprox_meta = self.headers.get('Warcprox-Meta')

        # Swallow headers that don't make sense to forward on, i.e. most
        # hop-by-hop headers, see http://tools.ietf.org/html/rfc2616#section-13.5
        # self.headers is an email.message.Message, which is case-insensitive
        # and doesn't throw KeyError in __delitem__
        for h in ('Connection', 'Proxy-Connection', 'Keep-Alive',
                'Proxy-Authenticate', 'Proxy-Authorization', 'Upgrade',
                'Warcprox-Meta'):
            del self.headers[h]

        # Add headers to the request
        # XXX in at least python3.3 str(self.headers) uses \n not \r\n :(
        #req_str += '\r\n'.join('{}: {}'.format(k,v) for (k,v) in self.headers.items())

        # Some sites expect first letter of header to be capitlized...
        for k, v in self.headers.items():
            req_str += k.capitalize() + ': ' + v + '\r\n'

        req = req_str.encode('utf-8') + b'\r\n'

        # Append message body if present to the request
        if 'Content-Length' in self.headers:
            req += self.rfile.read(int(self.headers['Content-Length']))

        self.logger.debug('req={}'.format(repr(req)))

        # Send it down the pipe!
        self._proxy_sock.sendall(req)

        # We want HTTPResponse's smarts about http and handling of
        # non-compliant servers. But HTTPResponse.read() doesn't return the raw
        # bytes read from the server, it unchunks them if they're chunked, and
        # might do other stuff. We want to send the raw bytes back to the
        # client. So we ignore the values returned by h.read() below. Instead
        # the ProxyingRecordingHTTPResponse takes care of sending the raw bytes
        # to the proxy client.

        # Proxy and record the response
        h = ProxyingRecordingHTTPResponse(self._proxy_sock,
                proxy_dest=self.connection,
                digest_algorithm=self.server.digest_algorithm,
                path=self.path)
        h.begin()

        buf = h.read(self.warcprox_buff_size)
        while buf != b'':
            buf = h.read(self.warcprox_buff_size)

        self.log_request(h.status, h.recorder.len)

        remote_ip = self._proxy_sock.getpeername()[0]

        # Let's close off the remote end
        h.close()
        self._proxy_sock.close()

        recorded_url = RecordedUrl(url=self.url, request_data=req,
                response_recorder=h.recorder, remote_ip=remote_ip,
                warcprox_meta=warcprox_meta, status=h.status,
                command=self.command)

        self.logger.debug('Queuing ' + str(self.url))
        self.server.recorded_url_q.put(recorded_url)

    def _handle_custom_record(self, type_):
        request_data = ''

        if type_ == 'metadata':
            # use custom metadata scheme
            self.url = self.path.replace('http:/', 'metadata:/')
        else:
            self.url = self.path

        if 'Content-Length' in self.headers and 'Content-Type' in self.headers:
            request_data += self.rfile.read(int(self.headers['Content-Length']))

            warcprox_meta = self.headers.get('Warcprox-Meta')

            rec_custom = RecordedUrl(url=self.url,
                                     request_data=request_data,
                                     response_recorder=None,
                                     remote_ip=b'',
                                     warcprox_meta=warcprox_meta,
                                     content_type=self.headers['Content-Type'],
                                     custom_type=type_)

            self.server.recorded_url_q.put(rec_custom)

        self.send_response(204, 'OK')
        self.end_headers()


class RecordedUrl(object):
    def __init__(self, url, request_data, response_recorder, remote_ip,
                 warcprox_meta=None, status=None, content_type='', command='',
                 custom_type=None):
        # XXX should test what happens with non-ascii url (when does
        # url-encoding happen?)
        if type(url) is not bytes:
            self.url = url.encode('ascii')
        else:
            self.url = url

        if type(remote_ip) is not bytes:
            self.remote_ip = remote_ip.encode('ascii')
        else:
            self.remote_ip = remote_ip

        self.request_data = request_data
        self.response_recorder = response_recorder

        if self.response_recorder.memento_datetime:
            self.datetime = self.response_recorder.memento_datetime
            if self.response_recorder.memento_link_original:
                self.url = self.response_recorder.memento_link_original
        else:
            self.datetime = datetime.now()

        # Optional metadata dict, if any, passed to warcprox
        if warcprox_meta:
            self.warcprox_meta = json.loads(warcprox_meta)
        else:
            self.warcprox_meta = {}

        self.status = status

        self.content_type = content_type

        self.command = command.upper()

        self.custom_type = custom_type

class PooledMixIn(socketserver.ThreadingMixIn):
    def process_request(self, request, client_address):
        if hasattr(self, 'pool') and self.pool:
            self.pool.submit(self.process_request_thread, request, client_address)
        else:
            socketserver.ThreadingMixIn.process_request(self, request, client_address)


class WarcProxy(socketserver.ThreadingMixIn, http_server.HTTPServer):
    logger = logging.getLogger("warcprox.warcprox.WarcProxy")

    def __init__(self, server_address=('localhost', 8000),
            req_handler_class=WarcProxyHandler, bind_and_activate=True,
            ca=None, recorded_url_q=None, digest_algorithm='sha1',
            buff_size=None, timeout=None, max_threads=None):

        http_server.HTTPServer.__init__(self, server_address, req_handler_class, bind_and_activate)

        self.digest_algorithm = digest_algorithm

        if ca is not None:
            self.ca = ca
        else:
            ca_name = 'Warcprox CA on {}'.format(socket.gethostname())[:64]
            self.ca = CertificateAuthority(ca_file='warcprox-ca.pem',
                                           certs_dir='./warcprox-ca',
                                           ca_name=ca_name)

        if recorded_url_q is not None:
            self.recorded_url_q = recorded_url_q
        else:
            self.recorded_url_q = queue.Queue()

        self.pool = None
        if max_threads is not None:
            try:
                self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=max_threads)
            except ValueError:
                pass

        if timeout:
            MitmProxyHandler.warcprox_timeout = timeout

        if buff_size:
            MitmProxyHandler.warcprox_buff_size = buff_size

    def server_activate(self):
        http_server.HTTPServer.server_activate(self)
        self.logger.info('WarcProxy listening on {0}:{1}'.format(self.server_address[0], self.server_address[1]))

    def server_close(self):
        self.logger.info('WarcProxy shutting down')
        http_server.HTTPServer.server_close(self)

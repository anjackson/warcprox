# vim:set sw=4 et:

from __future__ import absolute_import

try:
    import queue
except ImportError:
    import Queue as queue

import logging
import threading
import os
import hashlib
import time
import socket
import base64
import fcntl
import shutil
from datetime import datetime
import hanzo.httptools
from hanzo import warctools
import warcprox
import json

class WarcWriter(object):
    logger = logging.getLogger("warcprox.warcwriter.WarcWriter")

    # port is only used for warc filename
    def __init__(self, directory='./warcs', rollover_size=1000000000,
            rollover_idle_time=None,
            gzip=False, prefix='WARCPROX', port=0,
            digest_algorithm='sha1', base32=False, dedup_db=None,
            playback_index_db=None, skip_info=False,
            write_in_place=False):

        self.rollover_size = rollover_size
        self.rollover_idle_time = rollover_idle_time

        self.gzip = gzip
        self.digest_algorithm = digest_algorithm
        self.base32 = base32
        self.dedup_db = dedup_db

        self.playback_index_db = playback_index_db

        # warc path and filename stuff
        self.directory = directory
        self.prefix = prefix
        self.port = port

        # skip writing warcinfo
        self.skip_info = skip_info

        # don't write to a '.open' file first
        self.write_in_place = write_in_place
        self._f = None
        self._fpath = None
        self._serial = 0

        self._last_activity = time.time()

        if not os.path.exists(directory):
            self.logger.info("warc destination directory {} doesn't exist, creating it".format(directory))
            os.mkdir(directory)


    # returns a tuple (principal_record, request_record) where principal_record is either a response or revisit record
    def build_warc_records(self, recorded_url):
        warc_json_metadata = recorded_url.warcprox_meta.get('json_metadata')

        dt = None
        if warc_json_metadata:
            timestamp = warc_json_metadata.pop('timestamp', '')
            if timestamp:
                dt = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S.%f")

        if not dt:
            dt = recorded_url.datetime

        if not dt:
            dt = datetime.utcnow()

        warc_date = warctools.warc.warc_datetime_str(dt)

        dedup_info = None

        # metadata special case
        if recorded_url.custom_type == 'metadata':
            metadata_rec = self.build_warc_record(url=recorded_url.url,
                                                  warc_date=warc_date,
                                                  data=recorded_url.request_data,
                                                  warc_type=warctools.WarcRecord.METADATA,
                                                  content_type=recorded_url.content_type,
                                                  warc_json_metadata=warc_json_metadata)
            return [metadata_rec]

        # resource special case
        if recorded_url.custom_type == 'resource':
            metadata_rec = self.build_warc_record(url=recorded_url.url,
                                                  warc_date=warc_date,
                                                  data=recorded_url.request_data,
                                                  warc_type=warctools.WarcRecord.RESOURCE,
                                                  content_type=recorded_url.content_type,
                                                  warc_json_metadata=warc_json_metadata)
            return [metadata_rec]

        if self.dedup_db is not None and recorded_url.response_recorder.payload_digest is not None:
            key = self.digest_str(recorded_url.response_recorder.payload_digest)
            dedup_info = self.dedup_db.lookup(key, recorded_url)

        if dedup_info is not None:
            # skip flag is set, then skip writing revisit record
            if dedup_info.get('skip', False):
                return None

            # revisit record
            recorded_url.response_recorder.tempfile.seek(0)
            if recorded_url.response_recorder.payload_offset is not None:
                response_header_block = recorded_url.response_recorder.tempfile.read(recorded_url.response_recorder.payload_offset)
            else:
                response_header_block = recorded_url.response_recorder.tempfile.read()

            principal_record = self.build_warc_record(
                    url=recorded_url.url, warc_date=warc_date,
                    data=response_header_block,
                    warc_type=warctools.WarcRecord.REVISIT,
                    refers_to=dedup_info['i'],
                    refers_to_target_uri=dedup_info['u'],
                    refers_to_date=dedup_info['d'],
                    payload_digest=self.digest_str(recorded_url.response_recorder.payload_digest),
                    profile=warctools.WarcRecord.PROFILE_IDENTICAL_PAYLOAD_DIGEST,
                    content_type=hanzo.httptools.ResponseMessage.CONTENT_TYPE,
                    remote_ip=recorded_url.remote_ip)
        else:
            # response record
            principal_record = self.build_warc_record(
                    url=recorded_url.url, warc_date=warc_date,
                    recorder=recorded_url.response_recorder,
                    warc_type=warctools.WarcRecord.RESPONSE,
                    content_type=hanzo.httptools.ResponseMessage.CONTENT_TYPE,
                    remote_ip=recorded_url.remote_ip)

        if (self.dedup_db and hasattr(self.dedup_db, 'skip_request')
            and self.dedup_db.skip_request(recorded_url)):
            request_record = None
        else:
            request_record = self.build_warc_record(
                    url=recorded_url.url, warc_date=warc_date,
                    data=recorded_url.request_data,
                    warc_type=warctools.WarcRecord.REQUEST,
                    content_type=hanzo.httptools.RequestMessage.CONTENT_TYPE,
                    concurrent_to=principal_record.id)

        return principal_record, request_record


    def digest_str(self, hash_obj):
        return hash_obj.name.encode('utf-8') + b':' + (base64.b32encode(hash_obj.digest()) if self.base32 else hash_obj.hexdigest().encode('ascii'))


    def build_warc_record(self, url, warc_date=None, recorder=None, data=None,
        concurrent_to=None, warc_type=None, content_type=None, remote_ip=None,
        profile=None, refers_to=None, refers_to_target_uri=None,
        refers_to_date=None, payload_digest=None, warc_json_metadata=None):

        if warc_date is None:
            warc_date = warctools.warc.warc_datetime_str(datetime.utcnow())

        record_id = warctools.WarcRecord.random_warc_uuid()

        headers = []
        if warc_type is not None:
            headers.append((warctools.WarcRecord.TYPE, warc_type))
        headers.append((warctools.WarcRecord.ID, record_id))
        headers.append((warctools.WarcRecord.DATE, warc_date))
        headers.append((warctools.WarcRecord.URL, url))
        if remote_ip is not None:
            headers.append((warctools.WarcRecord.IP_ADDRESS, remote_ip))
        if profile is not None:
            headers.append((warctools.WarcRecord.PROFILE, profile))
        if refers_to is not None:
            headers.append((warctools.WarcRecord.REFERS_TO, refers_to))
        if refers_to_target_uri is not None:
            headers.append((warctools.WarcRecord.REFERS_TO_TARGET_URI, refers_to_target_uri))
        if refers_to_date is not None:
            headers.append((warctools.WarcRecord.REFERS_TO_DATE, refers_to_date))
        if concurrent_to is not None:
            headers.append((warctools.WarcRecord.CONCURRENT_TO, concurrent_to))
        if content_type is not None:
            headers.append((warctools.WarcRecord.CONTENT_TYPE, content_type))
        if payload_digest is not None:
            headers.append((warctools.WarcRecord.PAYLOAD_DIGEST, payload_digest))
        if warc_json_metadata is not None:
            print('WARC Metadata: ', warc_json_metadata)
            headers.append(('WARC-Json-Metadata', json.dumps(warc_json_metadata)))

        if recorder is not None:
            headers.append((warctools.WarcRecord.CONTENT_LENGTH, str(len(recorder)).encode('latin1')))
            headers.append((warctools.WarcRecord.BLOCK_DIGEST,
                self.digest_str(recorder.block_digest)))
            if recorder.payload_digest is not None:
                headers.append((warctools.WarcRecord.PAYLOAD_DIGEST,
                    self.digest_str(recorder.payload_digest)))

            recorder.tempfile.seek(0)
            record = warctools.WarcRecord(headers=headers, content_file=recorder.tempfile)

        else:
            headers.append((warctools.WarcRecord.CONTENT_LENGTH, str(len(data)).encode('latin1')))
            block_digest = hashlib.new(self.digest_algorithm, data)
            headers.append((warctools.WarcRecord.BLOCK_DIGEST,
                self.digest_str(block_digest)))

            content_tuple = content_type, data
            record = warctools.WarcRecord(headers=headers, content=content_tuple)

        return record


    def timestamp17(self):
        now = datetime.utcnow()
        return '{}{}'.format(now.strftime('%Y%m%d%H%M%S'), now.microsecond//1000)

    def on_check_rollover(self):
        if (self._f is not None
             and self.rollover_idle_time is not None
             and self.rollover_idle_time > 0
             and time.time() - self._last_activity > self.rollover_idle_time):
            self.logger.debug('rolling over warc file after {} seconds idle'.format(time.time() - self._last_activity))
            self.close_writer()
            return False

        return True

    def close_writer(self):
        if self._fpath:
            self.logger.info('closing {0}'.format(self._f_finalname))
            if self.write_in_place:
                fcntl.flock(self._f, fcntl.LOCK_UN)
            self._f.close()
            if not self.write_in_place:
                finalpath = os.path.sep.join([self.directory, self._f_finalname])
                os.rename(self._fpath, finalpath)

            self._fpath = None
            self._f = None

    def _build_warcinfo_record(self, filename):
        warc_record_date = warctools.warc.warc_datetime_str(datetime.utcnow())
        record_id = warctools.WarcRecord.random_warc_uuid()

        headers = []
        headers.append((warctools.WarcRecord.ID, record_id))
        headers.append((warctools.WarcRecord.TYPE, warctools.WarcRecord.WARCINFO))
        headers.append((warctools.WarcRecord.FILENAME, filename.encode('latin1')))
        headers.append((warctools.WarcRecord.DATE, warc_record_date))

        warcinfo_fields = []
        #warcinfo_fields.append(b'software: warcprox ' + warcprox.version_bytes)
        warcinfo_fields.append(b'software: webrecorder.io 2.0 (warcprox ' + warcprox.version_bytes + ')')
        hostname = socket.gethostname()
        warcinfo_fields.append('hostname: {}'.format(hostname).encode('latin1'))
        try:
            host_ip = socket.gethostbyname(hostname)
        except:
            host_ip = '127.0.0.1'
        warcinfo_fields.append('ip: {0}'.format(host_ip.encode('latin1')))
        warcinfo_fields.append(b'format: WARC File Format 1.0')
        # warcinfo_fields.append('robots: ignore')
        # warcinfo_fields.append('description: {0}'.format(self.description))
        # warcinfo_fields.append('isPartOf: {0}'.format(self.is_part_of))
        data = b'\r\n'.join(warcinfo_fields) + b'\r\n'

        record = warctools.WarcRecord(headers=headers, content=(b'application/warc-fields', data))

        return record


    # <!-- <property name="template" value="${prefix}-${timestamp17}-${serialno}-${heritrix.pid}~${heritrix.hostname}~${heritrix.port}" /> -->
    def _writer(self, warcprox_meta):
        if self._fpath and os.path.getsize(self._fpath) > self.rollover_size:
            self.close_writer()

        if self._f == None:
            prefix = warcprox_meta.get('name_prefix')
            if not prefix:
                prefix = warcprox_meta.get('sesh_id')
                if prefix:
                    prefix = prefix.replace(':', '-')

            if not prefix:
                prefix = self.prefix

            writer_type = warcprox_meta.get('writer_type', '')

            self._f_finalname = '{}-{}-{:05d}-{}-{}{}.warc{}'.format(
                    prefix, self.timestamp17(), self._serial, os.getpid(),
                    socket.gethostname(), writer_type, '.gz' if self.gzip else '')

            filename = self._f_finalname
            if not self.write_in_place:
                filename += '.open'

            self._fpath = os.path.sep.join([self.directory, filename])

            self._f = open(self._fpath, 'w+b')
            if self.write_in_place:
                fcntl.flock(self._f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                if self.playback_index_db and hasattr(self.playback_index_db, 'on_init_file'):
                    filename = os.path.basename(self._fpath)
                    self.playback_index_db.on_init_file(filename, warcprox_meta)

            if not self.skip_info:
                warcinfo_record = self._build_warcinfo_record(self._f_finalname)
                self.logger.debug('warcinfo_record.headers={}'.format(warcinfo_record.headers))
                warcinfo_record.write_to(self._f, gzip=self.gzip)

            self._serial += 1

        return self._f


    def _final_tasks(self, recorded_url, recordset, recordset_offset, record_length, writer):
        digest_key = None

        # digest only for non custom types?
        if not recorded_url.custom_type and recorded_url.response_recorder:
            if self.dedup_db or self.playback_index_db:
                digest_key = self.digest_str(recorded_url.response_recorder.payload_digest)

            if self.dedup_db is not None:
                self.dedup_db.save_digest(digest_key,
                                          recordset[0],
                                          recorded_url,
                                          recordset_offset)

        if self.playback_index_db is not None:
            self.playback_index_db.save_url(self._f_finalname,
                                            recordset[0],
                                            recorded_url,
                                            recordset_offset,
                                            record_length,
                                            digest_key,
                                            writer)

        if recorded_url.response_recorder:
            recorded_url.response_recorder.tempfile.close()

    def write_records(self, recorded_url):
        recordset = self.build_warc_records(recorded_url)

        # if writing was skipped, just return
        if not recordset:
            return

        writer = self._writer(recorded_url.warcprox_meta)
        recordset_offset = writer.tell()

        for record in recordset:
            offset = writer.tell()
            record.write_to(writer, gzip=self.gzip)
            self.logger.debug('wrote warc record: warc_type={} content_length={} url={} warc={} offset={}'.format(
                    record.get_header(warctools.WarcRecord.TYPE),
                    record.get_header(warctools.WarcRecord.CONTENT_LENGTH),
                    record.get_header(warctools.WarcRecord.URL),
                    self._fpath, offset))

        writer.flush()
        record_length = writer.tell() - recordset_offset

        self._final_tasks(recorded_url, recordset, recordset_offset, record_length, writer)

        self._last_activity = time.time()


class MultiWarcWriter(WarcWriter):
    """ Open multiple WarcWriters based on specified
        target dir param. Keep each one open until
        the rollover_idle_timeout has elapsed.
    """
    def __init__(self, *args, **kwargs):
        super(MultiWarcWriter, self).__init__(*args, **kwargs)
        self.output_dir_key = kwargs.get('output_dir', 'output_dir')
        self.writers = {}

        if len(args) > 0:
            args = args[1:]
        else:
            kwargs.pop('directory', '')

        self.args = args
        self.kwargs = kwargs

        self.abs_dir = os.path.abspath(self.directory)

    def write_records(self, recorded_url):
        target = recorded_url.warcprox_meta.get(self.output_dir_key, 'default')
        writer_type = recorded_url.warcprox_meta.get('writer_type', 'def')

        new_dir = os.path.join(self.directory, target)

        if target not in self.writers:
            if not os.path.isdir(new_dir):
                os.makedirs(new_dir)

            self.writers[target] = {}

        writers = self.writers[target]

        if writer_type not in writers:
            writers[writer_type] = WarcWriter(new_dir, *self.args, **self.kwargs)

        writers[writer_type].write_records(recorded_url)

    def on_check_rollover(self):
        for k, writers in list(self.writers.items()):
            for writer in writers.values():
                if not writer.on_check_rollover():
                    del self.writers[k]

    def close_writer(self):
        for writers in self.writers.values():
            for writer in writers.values():
                writer.close_writer()

        self.writers = {}

    def close_coll_writer_and_delete(self, output_dir):
        try:
            writers = self.writers.pop(output_dir)
            for writer in writers.values():
                writer.close_writer()
        except KeyError:
            pass

        parent_dir = os.path.dirname(output_dir.rstrip(os.path.sep))
        self.delete_dir(parent_dir)

    def delete_dir(self, dir_):
        dir_ = os.path.abspath(dir_)
        common = os.path.commonprefix([self.abs_dir, dir_])
        if not common.startswith(self.abs_dir):
            print('Attempt to delete invalid path: ' + dir_)
            return False

        if os.path.isdir(dir_):
            print('*** Deleting: ' + dir_)
            shutil.rmtree(dir_)
            return True


class WarcWriterThread(threading.Thread):
    logger = logging.getLogger("warcprox.warcwriter.WarcWriterThread")

    def __init__(self, recorded_url_q=None, warc_writer=None):
        """recorded_url_q is a queue.Queue of warcprox.warcprox.RecordedUrl."""
        threading.Thread.__init__(self, name='WarcWriterThread')
        self.recorded_url_q = recorded_url_q
        self.stop = threading.Event()
        if warc_writer:
            self.warc_writer = warc_writer
        else:
            self.warc_writer = WarcWriter()

    def run(self):
        self.logger.info('WarcWriterThread starting, directory={} gzip={} rollover_size={} rollover_idle_time={} prefix={} port={}'.format(
                os.path.abspath(self.warc_writer.directory), self.warc_writer.gzip, self.warc_writer.rollover_size,
                self.warc_writer.rollover_idle_time, self.warc_writer.prefix, self.warc_writer.port))

        self._last_sync = time.time()

        while not self.stop.is_set():
            try:
                recorded_url = self.recorded_url_q.get(block=True, timeout=0.5)
                self.logger.info("recorded_url.warcprox_meta={} for {}".format(recorded_url.warcprox_meta, recorded_url.url))
                self.warc_writer.write_records(recorded_url)
            except queue.Empty:
                self.warc_writer.on_check_rollover()

                if time.time() - self._last_sync > 60:
                    if self.warc_writer.dedup_db:
                        self.warc_writer.dedup_db.sync()
                    if self.warc_writer.playback_index_db:
                        self.warc_writer.playback_index_db.sync()
                    self._last_sync = time.time()
            except Exception as e:
                import traceback
                traceback.print_exc(e)

        self.logger.info('WarcWriterThread shutting down')
        self.warc_writer.close_writer();


class CloseAndDeleteCollThread(threading.Thread):
    def __init__(self, multiwriter, redis):
        threading.Thread.__init__(self, name='CloseAndDeleteCollThread')
        self.multiwriter = multiwriter
        self.redis = redis
        self.pubsub = self.redis.pubsub()
        self.pubsub.subscribe(['delete_coll', 'delete_user'])
        self.daemon = True

    def run(self):
        for item in self.pubsub.listen():
            print(item)
            if item['type'] == 'message':
                if item['channel'] == 'delete_coll':
                    self.multiwriter.close_coll_writer_and_delete(item['data'])
                elif item['channel'] == 'delete_user':
                    self.multiwriter.delete_dir(item['data'])

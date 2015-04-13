import redis
import json
import logging
import surt
import re

from datetime import datetime, timedelta
from hanzo import warctools
from itertools import imap
from collections import OrderedDict


class RedisDedupDb(object):
    T14_STRIP = re.compile(r'[^\d]')

    def __init__(self, redis_url, sesh_timeout,
                 dupe_timeout, max_size, sesh_key='sesh_id'):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.redis_url = redis_url
        self.redis = redis.StrictRedis.from_url(redis_url)
        self.sesh_key = sesh_key

        self.sesh_timeout = sesh_timeout
        self.dupe_delta = timedelta(seconds=dupe_timeout)
        self.dupe_timeout = dupe_timeout

        self.max_size = max_size
        self.totals_key = 'totals'

    def close(self):
        pass

    def sync(self):
        pass

    def save_digest(self, digest, response_record, recorded_url, offset):
        if ((response_record.get_header(warctools.WarcRecord.TYPE) !=
             warctools.WarcRecord.RESPONSE) or
            recorded_url.response_recorder.payload_size() == 0):
            return

        sesh = recorded_url.warcprox_meta.get(self.sesh_key, 'default')
        key = sesh

        record_id = response_record.get_header(warctools.WarcRecord.ID).decode('latin1')
        url = response_record.get_header(warctools.WarcRecord.URL).decode('latin1')
        date = response_record.get_header(warctools.WarcRecord.DATE).decode('latin1')

        py_value = {'i': record_id,
                    'u': url,
                    'd': date}

        json_value = json.dumps(py_value, separators=(',',':'))

        self.redis.hset(key, digest, json_value.encode('utf-8'))

        self.logger.debug('redis dedup saved {}:{}'.format(digest, json_value))

    def lookup(self, digest, recorded_url=None):
        sesh = recorded_url.warcprox_meta.get(self.sesh_key, 'default')
        key = sesh

        if self.max_size:
            total_len = self.redis.hget(key, 'total_len')
            total_len = int(total_len) if total_len else 0
            if total_len >= self.max_size:
                return dict(skip=True)


        if not digest:
            return None

        json_result = self.redis.hget(key, digest)

        if not json_result:
            return None

        result = json.loads(json_result.decode('utf-8'))

        result['i'] = result['i'].encode('latin1')
        result['u'] = result['u'].encode('latin1')
        result['d'] = result['d'].encode('latin1')

        dt = self.iso_date_to_datetime(result['d'])
        now = datetime.now()

        url = recorded_url.url

        if self.dupe_timeout and (now - dt) <= self.dupe_delta:
            # skip only if urls also match, otherwise url-agnostic
            # revisit is needed
            print('DUPE')
            if url and result['u'] == url:
                print('SKIPPING')
                result['skip'] = True

            # update redis key to indicate 'skip'
            #dupe_key = key + ':p:' + url
            #self.redis.setex(dupe_key, self.dupe_timeout, 1)

        return result

    #def save_url(self, digest, response_record, offset, length, filename, recorded_url):
    def save_url(self, filename, response_record, recorded_url, offset, length, digest):
        url = response_record.get_header(warctools.WarcRecord.URL).decode('latin1')
        date = response_record.get_header(warctools.WarcRecord.DATE).decode('latin1')

        sesh = recorded_url.warcprox_meta.get(self.sesh_key, 'default')

        key = sesh

        with redis.utils.pipeline(self.redis) as pi:
            pi.hincrby(key, 'total_len', length)
            pi.hincrby(key, 'num_urls', 1)

            pi.hincrby(self.totals_key, 'total_len', length)
            pi.hincrby(self.totals_key, 'num_urls', 1)

            #if pi.setnx(dupe_key, 0):
            #    dupe_key = key + ':p:' + url
            #    pi.expire(dupe_key, self.dupe_timeout)

            self._save_cdx(pi, key, url, date, response_record, recorded_url.status,
                           digest, length, offset, filename)

    def _save_cdx(self, pi, key, url, date, response_record, status,
                  digest, length, offset, filename):

        url_key = surt.surt(url)

        key = 'cdxj:' + key

        if (response_record.get_header(warctools.WarcRecord.TYPE) ==
            warctools.WarcRecord.REVISIT):
            mimetype = 'warc/revisit'
        else:
            mimetype = '-'

        cdx = OrderedDict()
        cdx['url'] = url
        if mimetype and mimetype != '-':
            cdx['mime'] = mimetype
        if status and status != '-':
            cdx['status'] = status
        if digest and digest != '-':
            cdx['digest'] = digest
        cdx['length'] = length
        cdx['offset'] = offset
        cdx['filename'] = filename

        date = self.T14_STRIP.sub('', date)

        value = url_key + ' ' + date + ' ' + json.dumps(cdx)
        #value = '{} {} {} {} {} {} - - {} {} {}'.format(url_key, date, url, mimetype, status, digest, length, offset, filename)

        #self.redis.rpush(key, value)
        pi.zadd(key, 0, value)
        if self.sesh_timeout > 0:
            pi.expire(key, self.sesh_timeout)

    def iso_date_to_datetime(self, string):
        nums = self.T14_STRIP.split(string)
        if nums[-1] == '':
            nums = nums[:-1]

        the_datetime = datetime(*imap(int, nums))
        return the_datetime

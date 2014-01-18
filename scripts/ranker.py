#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (C) 2013 Freaxmind
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

__author__  = 'Freaxmind'
__email__   = 'freaxmind@freaxmind.pro'
__version__ = '0.1'
__license__ = 'GPLv3'


from ConfigParser import ConfigParser
import argparse
import urllib2
import urllib
import redis
import json
import sys
import os

# Python versions before 3.0 do not use UTF-8 encoding
# by default. To ensure that Unicode is handled properly
# throughout SleekXMPP, we will set the default encoding
# ourselves to UTF-8.
if sys.version_info < (3, 0):
    reload(sys)
    sys.setdefaultencoding('utf8')


class RankerThrottled(Exception):
    """
    VirusTotal API has limitations (4 req/min)
    raise this exception when it appends (HTTP Response Code: 204)
    """

    def __init__(self):
        Exception.__init__(self, 'VirusTotal API Throttled')


class Ranker(object):
    API_CONFIG_FILE = 'etc/api.ini'
    REDIS_HASHSET   = 'malwares'

    def __init__(self, scripted=False):
        """
        Initialize:
            - configuration
            - scripted
            - redis client
        """
        # init configuration
        self.config = ConfigParser()
        self.config.read(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', self.API_CONFIG_FILE))

        # init scripted mod
        self.scripted = scripted

        # init redis
        self.redis = redis.StrictRedis(host='localhost', port=6379, db=0)

    def parse(self, args):
        """Parse command line arguments (or any similar list)"""
        parser = argparse.ArgumentParser(description="Classifier of malware popularity (detection rate by VirusTotal)")
        parser.add_argument('--md5', '-m', required=False, help="MD5 fingerprint of the malware file")
        parser.add_argument('--pcaps', '-p', required=False, help="Directory path (ex: sample/) with pcap files: <md5_hash>.pcap)")
        parser.add_argument('--output', '-o', required=False, help="Write the JSON response in a file")
        parser.add_argument('--display', '-d', action='store_true', required=False, help="Display the JSON response")
        self.params = parser.parse_args(args)

    def dispatch(self):
        """Dispatch the action"""
        if self.params.md5:
            self.test_md5(self.params.md5)
        elif self.params.pcaps:
            self.test_pcaps(self.params.pcaps)
        else:
            raise Exception("No action set (--md5, --pcaps)")

    def test_md5(self, hash, return_json=True):
        """Test a malware hash with the API)"""
        # build the request
        report_url = self.config.get('VirusTotal', 'report_url')
        parameters = {'resource': hash, 'apikey': self.config.get('VirusTotal', 'key')}
        data = urllib.urlencode(parameters)
        req = urllib2.Request(report_url, data)

        # retrieve the response
        response = urllib2.urlopen(req)
        if response.getcode() == 204:
            raise RankerThrottled()

        body = response.read()

        # return the result (json or raw str)
        if return_json:
            return json.loads(body)
        else:
            return body

    def test_pcaps(self, path):
        """Test with a directory containing pcap files (<malware_md5_hash>.pcap)"""
        from time import sleep
        from glob import glob

        # TODO: use regexp instead of replace (but due to the API limitations, it's enough)
        for f in glob(os.path.join(path, '*.pcap')):
            md5 = f.replace('.pcap', '').replace(path, '')
            passed = False

            # skip if the key exists
            if self.redis.hget(self.REDIS_HASHSET, md5):
                print "%s already exists (skipped)" % md5
                continue

            # try to add the value
            while not passed:
                try:
                    res = self.test_md5(md5, False)
                    passed = True
                except RankerThrottled as e:
                    print "%s for %s (Sleeping for 10s)" % (e, md5)
                    sleep(10)

            self.redis.hset(self.REDIS_HASHSET, md5, res)
            print "Hash set: %s" % md5

    def __handle_response(self, response):
        """Handle the program output (only if the scripted flag is set)"""
        if not self.scripted:
            return

        if self.params.display:
            print response
        if self.params.output:
            open(self.params.output, 'w').write(response)


if __name__ == '__main__':
    """Simply use the command line arguments to set and execute the script"""
    r = Ranker(scripted=True)
    r.parse(sys.argv[1:])
    r.dispatch()

"""
import networkx as nx
g = nx.Graph()
g.add_node(v)
g.add_edge(v, md5)
nx.write_gefx(g, 'file.gexf')
"""

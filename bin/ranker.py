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
import simplejson
import argparse
import postfile
import urllib2
import urllib
import sys
import os

class Ranker(object):
    API_CONFIG_FILE = 'etc/api.ini'

    def __init__(self):
        self.config = ConfigParser()
        self.config.read(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', self.API_CONFIG_FILE))
        self.parser = argparse.ArgumentParser(description="Classifier of malware popularity (detection rate by VirusTotal)")

    def parse(self, args):
        self.parser.add_argument('--md5', '-m', required=False, help="MD5 fingerprint of the malware file")
        #self.parser.add_argument('--file', '-f', required=False, help="File path of the malware")
        self.parser.add_argument('--output', '-o', required=False, help="Write the JSON response in a file")
        self.parser.add_argument('--silent', '-s', action='store_true', required=False, help="Do not display the JSON response")
        self.params = self.parser.parse_args(args)

    def dispatch(self):
        if self.params.md5:
            self.test_md5(self.params.md5)
        else:
            raise Exception("No action set (--md5, --file)")

    def test_md5(self, hash):
        parameters = {'resource': hash, 'apikey': self.config.get('VirusTotal', 'key')}
        data = urllib.urlencode(parameters)
        req = urllib2.Request(self.config.get('VirusTotal', 'report_url'), data)

        response = urllib2.urlopen(req)

        json = response.read()
        self.__handle_response(json)

        return json

    def __handle_response(self, response):
        if not self.params.silent:
            print response
        if self.params.output:
            open(self.params.output, 'w').write(response)

if __name__ == '__main__':
    r = Ranker()
    r.parse(sys.argv[1:])
    r.dispatch()

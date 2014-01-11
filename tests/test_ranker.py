# -*- coding: utf-8 -*-

import unittest
from bin.ranker import Ranker

class TestRanker(unittest.TestCase):

    def setUp(self):
        self.ranker = Ranker()

    def test_md5(self):
        res = self.test_md5('99017f6eebbac24f351415dd410d522d')
        # test

if __name__ == '__main__':
    unittest.main()

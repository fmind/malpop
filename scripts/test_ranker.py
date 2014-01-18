#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ranker import Ranker
import unittest


class TestRanker(unittest.TestCase):

    def setUp(self):
        self.ranker = Ranker()

    def test_md5(self):
        res = self.ranker.test_md5('99017f6eebbac24f351415dd410d522d')
        self.assertEqual(48, res['total'])
        self.assertEqual(42, res['positives'])


if __name__ == '__main__':
    unittest.main()

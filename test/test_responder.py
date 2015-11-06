from collections import namedtuple
from mock import patch
from mock import Mock
import sys
import unittest

import os
import md5
from gladius import ResponderHandler

class TestGladius(unittest.TestCase):
    def setUp(self):
        self.handler = ResponderHandler()

    def test_gladius_handler_cache(self):
        self.assertEquals([], self.handler.cache)

if __name__ == '__main__':
    unittest.main()

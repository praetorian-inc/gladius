import unittest
from mock import patch

import os
from gladius import find_file

class FindFileTest(unittest.TestCase):
    @patch("gladius.os")
    def test_find_file(self, mock_os):
        mock_os.walk.return_value = ['root', ['dir1', 'dir2'], ['f1', 'f2']]

        filepath = find_file('f2')

        self.assertEqual(filepath, os.path.join('root', 'f2'))

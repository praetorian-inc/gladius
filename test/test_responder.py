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

    def test_responder_correctly_pass_get_lines(self):
        event = 'testing'
        self.handler.get_lines = Mock()
        self.handler.get_lines.return_value = []
        self.handler.process(event)

        self.handler.get_lines.assert_called_with(event)

    def test_responder_process_event_blank_lines(self):
        event = 'testing'
        self.handler.get_lines = Mock()
        self.handler.get_lines.return_value = [[]]
        self.handler.call_hashcat = Mock()
        self.handler.process(event)

        self.handler.call_hashcat.assert_not_called()

    @patch('gladius.info')
    def test_responder_process_event_ntlmv2(self, mock_info):
        for t, curr_hashtype in self.handler.types:
            if t == 'ntlmv2':
                hashtype = str(curr_hashtype)

        Event = namedtuple("Event", ['src_path'])
        src_path = 'SMB-NTLMv2-TestPath'
        event = Event(src_path)

        self.handler.get_lines = Mock()
        self.handler.get_lines.return_value = [event.src_path]
        self.handler.call_hashcat = Mock()
        self.handler.process(event)

        self.handler.call_hashcat.assert_called_with(hashtype, [event.src_path])

    @patch('gladius.info')
    def test_responder_process_event_ntlmv1(self, mock_info):
        for t, curr_hashtype in self.handler.types:
            if t == 'ntlmv1':
                hashtype = str(curr_hashtype)

        Event = namedtuple("Event", ['src_path'])
        src_path = 'SMB-NTLMv1-TestPath'
        event = Event(src_path)

        self.handler.get_lines = Mock()
        self.handler.get_lines.return_value = [event.src_path]
        self.handler.call_hashcat = Mock()
        self.handler.process(event)

        self.handler.call_hashcat.assert_called_with(hashtype, [event.src_path])

    @patch('gladius.info')
    def test_responder_process_event_ntlm(self, mock_info):
        for t, curr_hashtype in self.handler.types:
            if t == 'hashdump':
                hashtype = str(curr_hashtype)

        Event = namedtuple("Event", ['src_path'])
        src_path = 'SMB-hashdump-TestPath'
        event = Event(src_path)

        self.handler.get_lines = Mock()
        self.handler.get_lines.return_value = [event.src_path]
        self.handler.call_hashcat = Mock()
        self.handler.process(event)

        self.handler.call_hashcat.assert_called_with(hashtype, [event.src_path])
if __name__ == '__main__':
    unittest.main()

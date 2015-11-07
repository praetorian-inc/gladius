from collections import namedtuple
from mock import patch
from mock import Mock, mock_open
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

    @patch('gladius.warning')
    @patch('gladius.config')
    @patch('gladius.os')
    def test_responder_accept_eula(self, mock_os, mock_config, mock_info):
        mock_os.path = Mock()
        mock_os.path.join.return_value = '/root/tools/hashcat/eula.accepted'

        mock_config.return_value = 'testing'

        m = mock_open()
        with patch('gladius.open', m, create=True):
            self.handler.accept_eula('/root/tools/hashcat')

        handle = m()
        handle.write.assert_called_with('1\0\0\0')

    @patch('gladius.config')
    def test_responder_config_parse(self, mock_config):
        results = ('hashcat', 'ruleset', 'wordlist')
        mock_config.get.side_effect = results
        return_value = self.handler.get_configs()
        self.assertEqual(results, return_value)

    @patch('gladius.config')
    @patch('gladius.error')
    def test_responder_error_hashcat_config_parse(self, mock_error, mock_config):
        results = ['', 'ruleset', 'wordlist']

        mock_config.get.side_effect = results
        self.handler.get_configs()

        self.assertEquals(mock_error.call_count, 1)

    @patch('gladius.config')
    @patch('gladius.error')
    def test_responder_error_ruleset_config_parse(self, mock_error, mock_config):
        results = ['hashcat', '', 'wordlist']

        mock_config.get.side_effect = results
        self.handler.get_configs()

        self.assertEquals(mock_error.call_count, 1)

    @patch('gladius.config')
    @patch('gladius.error')
    def test_responder_error_wordlist_config_parse(self, mock_error, mock_config):
        results = ['hashcat', 'ruleset', '']

        mock_config.get.side_effect = results
        self.handler.get_configs()

        self.assertEquals(mock_error.call_count, 1)

    @patch('gladius.subprocess')
    @patch('gladius.os')
    def test_responder_call_hashcat(self, mock_os, mock_subprocess):
        self.handler.accept_eula = Mock()
        self.handler.get_configs = Mock()
        self.handler.get_configs.return_value = ['hashcat', 'ruleset', 'wordlist']

        outfile = Mock()
        outfile.name = 'outfile'
        self.handler.get_outfile = Mock()
        self.handler.get_outfile.return_value = outfile

        junkfile = Mock()
        junkfile.name = 'junkfile'
        self.handler.get_junkfile = Mock()
        self.handler.get_junkfile.return_value = junkfile

        tempfile = Mock()
        tempfile.name = 'tempfile'

        self.handler.get_tempfile = Mock()
        self.handler.get_tempfile.return_value = tempfile

        self.handler.outpath = 'outpath'

        mock_os.path = Mock()
        mock_os.path.exists.return_value = True

        mock_subprocess.Popen = Mock()

        self.handler.call_hashcat('5600', 'SMB-NTLMv2.txt')

        self.assertEqual(['hashcat', '-m', '5600', '-r', 'ruleset', '-o', 'outfile', 'junkfile', 'wordlist'], mock_subprocess.Popen.call_args[0][0])


if __name__ == '__main__':
    unittest.main()

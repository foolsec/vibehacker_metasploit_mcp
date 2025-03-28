"""
Tests for Metasploit Tools FastMCP Server
"""

import unittest
import os
from unittest.mock import patch, MagicMock
from main import mcp, list_exploits, list_payloads, generate_payload, scan_target

class TestMetasploitTools(unittest.TestCase):
    @patch('main.msf_client')
    def test_list_exploits(self, mock_msf_client):
        """Test that list_exploits returns filtered exploits"""
        # Setup mock
        mock_msf_client.modules.exploits = [
            'exploit/windows/smb/ms17_010_eternalblue',
            'exploit/linux/http/apache_struts',
            'exploit/multi/http/jenkins_script_console'
        ]
        
        # Test with search term
        result = list_exploits('windows')
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], 'exploit/windows/smb/ms17_010_eternalblue')
        
        # Test without search term
        result = list_exploits()
        self.assertEqual(len(result), 3)
    
    @patch('main.msf_client')
    def test_list_payloads(self, mock_msf_client):
        """Test that list_payloads returns filtered payloads"""
        # Setup mock
        mock_msf_client.modules.payloads = [
            'windows/meterpreter/reverse_tcp',
            'linux/x86/meterpreter/reverse_tcp',
            'windows/x64/meterpreter/reverse_https'
        ]
        
        # Test with platform filter
        result = list_payloads('windows')
        self.assertEqual(len(result), 2)
        
        # Test with platform and arch filter
        result = list_payloads('windows', 'x64')
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], 'windows/x64/meterpreter/reverse_https')
    
    @patch('subprocess.run')
    def test_generate_payload(self, mock_run):
        """Test payload generation"""
        # Setup mock
        mock_process = MagicMock()
        mock_process.stdout = "Payload generated successfully"
        mock_process.returncode = 0
        mock_run.return_value = mock_process
        
        result = generate_payload(
            'windows/meterpreter/reverse_tcp', 
            '192.168.1.100', 
            4444, 
            'exe'
        )
        
        # Verify subprocess was called with correct arguments
        mock_run.assert_called_once()
        cmd_arg = mock_run.call_args[0][0]
        self.assertIn('msfvenom', cmd_arg)
        self.assertIn('windows/meterpreter/reverse_tcp', cmd_arg)
        self.assertIn('LHOST=192.168.1.100', cmd_arg)
        self.assertIn('LPORT=4444', cmd_arg)
        self.assertIn('-f exe', cmd_arg)
    
    @patch('main.msf_client')
    def test_scan_target(self, mock_msf_client):
        """Test target scanning"""
        # Setup mock console
        mock_console = MagicMock()
        mock_console.run_single_command.return_value = {'data': 'Scan results'}
        
        # Setup mock console creation
        mock_msf_client.consoles.console.return_value = {'id': '1'}
        mock_msf_client.consoles.console.side_effect = [
            {'id': '1'},  # First call returns dict
            mock_console  # Second call returns the mock console object
        ]
        
        result = scan_target('192.168.1.0/24', 'basic')
        
        # Verify console commands were executed
        self.assertEqual(mock_console.run_single_command.call_count, 3)
        self.assertIn('Scan results', result)

if __name__ == "__main__":
    unittest.main()

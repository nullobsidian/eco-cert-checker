"""
Unit test for the `check_certificate` function.

This module contains unit tests for testing the functionality of the `check_certificate` function
from the `check_certificate` module. It verifies the correct identification and categorization of
SSL/TLS certificates based on their expiration and issue dates by simulating the output of the
OpenSSL command used within the `check_certificate` function.
"""

import unittest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

from check_certificate import check_certificate

class TestCheckCertificate(unittest.TestCase):
    """
    This test class is designed to unit test the functionality of the `check_certificate` function.
    """

    @patch("check_certificate.subprocess.run")
    def test_check_run(self, mock_run):
        """
        Tests the `check_certificate` function to ensure it correctly identifies a valid SSL 
        certificate.

        This test simulates the subprocess output of the openssl command, representing a certificate 
        that is currently valid (not expired and issued more than RECENT_THRESHOLD_DAYS ago). It 
        then checks that the function's return value matches the expected result for a valid 
        certificate.

        Args:
            mock_run (MagicMock): A mock of the `subprocess.run` function, allowing the simulation
                                  of subprocess output without executing the actual command.

        Asserts:
            Asserts that the result from `check_certificate` matches the expected dictionary 
            indicating a valid certificate status for the given IP and port.
        """
        future_date = datetime.now() + timedelta(days=365)  # Issued
        past_date = datetime.now() - timedelta(days=120)  # Recent Issued
        formatted_not_after = future_date.strftime("NotAfter: %b %d %H:%M:%S %Y GMT\n")
        formatted_not_before = past_date.strftime("NotBefore: %b %d %H:%M:%S %Y GMT\n")

        mock_output = formatted_not_before + formatted_not_after

        mock_process = MagicMock()
        mock_process.stdout = mock_output.encode("utf-8")
        mock_process.stderr = b""
        mock_process.returncode = 0
        mock_run.return_value = mock_process

        result = check_certificate("8.8.8.8", 443)
        expected = {
            "ip": "8.8.8.8",
            "port": 443,
            "status": "valid",
            "service": "SSL Certificate Check",
        }

        self.assertEqual(result, expected)


if __name__ == "__main__":
    unittest.main()

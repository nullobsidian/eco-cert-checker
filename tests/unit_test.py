import unittest
from unittest.mock import patch, MagicMock
from check_certificate import check_certificate
from datetime import datetime, timedelta


class TestCheckCertificate(unittest.TestCase):

    @patch("check_certificate.subprocess.run")
    def test_check_run(self, mock_run):
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

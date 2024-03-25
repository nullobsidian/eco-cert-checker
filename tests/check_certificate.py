"""
This module provides functionality for checking the SSL/TLS certificate status of a given IP address
and port by making a synchronous OpenSSL connection. 

Primarily used for unit testing the certificate verification process, ensuring that certificates are 
valid, not expired, and meet certain thresholds for expiration and issuance recency.

The current synchronous implementation serves as a foundationals step towards understanding 
and verifying the certificate checking process, with an eye towards asynchronous execution 
to improve performance and scalability, especially when integrating with larger, 
asynchronous systems or when checking multiple certificates concurrently.
"""

import subprocess
import datetime
import logging
import re

IP = "8.8.8.8"
PORT = 443
EXPIRE_THRESHOLD_DAYS = 30
RECENT_THRESHOLD_DAYS = 90

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def check_certificate(ip, port):
    """
    Synchronously checks the SSL/TLS certificate of a given IP address by making an OpenSSL
    connection. Logs various potential issues like connection timeouts, SSL errors, or certificate
    validity issues.

    Args:
        ip (str): The IP address to check the certificate for.
        port (int): The port number on which the server is listening for secure connections.

    Returns:
        dict: A dictionary containing the IP, status, and service information related to the
              certificate check, or None if an error occurred.
    """
    date_format = "%b %d %H:%M:%S %Y %Z"
    cmd = f"openssl s_client -connect {ip}:{port} -servername {ip}"
    not_after_regex = re.compile(
        r"NotAfter:\s*(\w{3} \d{2} \d{2}:\d{2}:\d{2} \d{4} GMT)"
    )
    not_before_regex = re.compile(
        r"NotBefore:\s*(\w{3} \d{2} \d{2}:\d{2}:\d{2} \d{4} GMT)"
    )

    try:
        process = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, check=False
        )
        stdout_output = process.stdout
        stderr_output = process.stderr
    except subprocess.CalledProcessError as e:
        logger.error(
            {
                "ip": ip,
                "port": port,
                "ERROR": "Command execution failed",
                "details": str(e),
            }
        )
        return {"ip": ip, "status": "command_error", "service": "SSL Certificate Check"}

    if "errno=60" in stderr_output:
        logger.error(
            {
                "ip": ip,
                "port": port,
                "ERROR": "Connection timed out",
                "detail": stderr_output,
            }
        )
        return {
            "ip": ip,
            "status": "connection_timeout",
            "service": "SSL Certificate Check",
        }

    elif "unexpected eof" in stderr_output:
        pass

    elif process.returncode != 0:
        logger.error(
            {
                "ip": ip,
                "port": port,
                "ERROR": "SSL connection failed",
                "detail": stderr_output,
            }
        )
        return {"ip": ip, "status": "ssl_error", "service": "SSL Certificate Check"}

    not_before_match = not_before_regex.search(stdout_output)
    not_after_match = not_after_regex.search(stdout_output)

    if not_before_match and not_after_match:
        not_before_str = not_before_match.group(1)
        not_after_str = not_after_match.group(1)
        try:
            not_before_date = datetime.datetime.strptime(not_before_str, date_format)
            not_after_date = datetime.datetime.strptime(not_after_str, date_format)
        except ValueError as e:
            logger.error(
                {"ip": ip, "ERROR": "Failed to parse the dates", "exception": str(e)}
            )
            return {
                "ip": ip,
                "status": "parse_error",
                "service": "SSL Certificate Check",
            }

        now = datetime.datetime.now()
        if not_after_date < now:
            return {
                "ip": ip,
                "port": port,
                "status": "expired",
                "service": "SSL Certificate Check",
            }
        elif (not_after_date - now).days <= EXPIRE_THRESHOLD_DAYS:
            return {
                "ip": ip,
                "port": port,
                "status": "expiring_soon",
                "service": "SSL Certificate Check",
            }
        elif (now - not_before_date).days <= RECENT_THRESHOLD_DAYS:
            return {
                "ip": ip,
                "port": port,
                "status": "recently_issued",
                "service": "SSL Certificate Check",
            }
        else:
            return {
                "ip": ip,
                "port": port,
                "status": "valid",
                "service": "SSL Certificate Check",
            }
    else:
        logger.error({"ip": ip, "ERROR": "Certificate dates not found"})
        return {
            "ip": ip,
            "status": "date_info_missing",
            "service": "SSL Certificate Check",
        }

check_certificate(IP, PORT)

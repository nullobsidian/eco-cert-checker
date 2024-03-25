import subprocess
import datetime
import logging
import re

ip = "8.8.8.8"
port = 443
expire_threshold_days = 30
recent_threshold_days = 90

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def check_certificate(ip, port):
    date_format = "%b %d %H:%M:%S %Y %Z"
    cmd = f"openssl s_client -connect {ip}:{port} -servername {ip}"
    not_after_regex = re.compile(
        r"NotAfter:\s*(\w{3} \d{2} \d{2}:\d{2}:\d{2} \d{4} GMT)"
    )
    not_before_regex = re.compile(
        r"NotBefore:\s*(\w{3} \d{2} \d{2}:\d{2}:\d{2} \d{4} GMT)"
    )

    try:
        process = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        stdout_output = str(process.stdout) if process.stdout is not None else ""
        stderr_output = str(process.stderr) if process.stderr is not None else ""
    except Exception as e:
        logger.error({"ip": ip, "port": port, "ERROR": str(e)})
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
        elif (not_after_date - now).days <= expire_threshold_days:
            return {
                "ip": ip,
                "port": port,
                "status": "expiring_soon",
                "service": "SSL Certificate Check",
            }
        elif (now - not_before_date).days <= recent_threshold_days:
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


check_certificate(ip, port)

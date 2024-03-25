import os
import re
import asyncio
import datetime
import ipaddress
from subprocess import PIPE
from aiohttp import ClientSession
from aio_statsd import StatsdClient
from aiologger import Logger
from aiologger.formatters.json import JsonFormatter
from asyncio.subprocess import create_subprocess_shell

# Config
SLACK_WEBHOOK_URL = os.getenv(
    "SLACK_WEBOOK_URL",
    "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
)
STATSD_SERVER = os.getenv("STATSD_SERVER", "10.10.4.14")
STATSD_PORT = int(os.getenv("STATSD_PORT", "8125"))
CONCURRENT_LIMIT = int(os.getenv("CONCURRENT_LIMIT", "5"))
EXPIRE_THRESHOLD_DAYS = 30
RECENT_THRESHOLD_DAYS = 90
TIMEOUT = int(os.getenv("TIMEOUT", "5"))

IP_FILE_PATH = os.getenv("IP_FILE_PATH", "takehome_ip_addresses.txt")
CA_FILE_PATH = os.getenv("CA_FILE_PATH", None)

# Service Config
SERVICE_CONFIG = {
    "Europa": {"network": ipaddress.ip_network("10.10.6.0/24"), "port": 4000},
    "Callisto": {"network": ipaddress.ip_network("10.10.8.0/24"), "port": 8000},
}

# statsd
statsd_client = StatsdClient(host=STATSD_SERVER, port=STATSD_PORT)

# logging
logger = Logger.with_default_handlers(level="DEBUG", formatter=JsonFormatter())


def get_service_details(ip):
    for service, config in SERVICE_CONFIG.items():
        if ipaddress.ip_address(ip) in config["network"]:
            return service, config["port"]
    return None, None


async def check_certificate(ip, semaphore):
    service, port = get_service_details(ip)
    if not service:
        await logger.error(
            {"ip": ip, "INFO": "IP address does not match any service configuration"}
        )
        return

    async with semaphore:
        date_format = "%b %d %H:%M:%S %Y %Z"
        cafile = f"-CAfile {CA_FILE_PATH}" if CA_FILE_PATH is not None else ""
        cmd = f"echo | openssl s_client -connect {ip}:{port} -servername {ip} {cafile}"
        not_after_regex = re.compile(
            r"NotAfter:\s*(\w{3} \d{2} \d{2}:\d{2}:\d{2} \d{4} GMT)"
        )
        not_before_regex = re.compile(
            r"NotBefore:\s*(\w{3} \d{2} \d{2}:\d{2}:\d{2} \d{4} GMT)"
        )

        try:
            process = await asyncio.create_subprocess_shell(
                cmd, stdout=PIPE, stderr=PIPE
            )
            stdout_output, stderr_output = await process.communicate()
            stdout_output = str(process.stdout) if process.stdout is not None else ""
            stderr_output = str(process.stderr) if process.stderr is not None else ""
        except Exception as e:
            await logger.error({"ip": ip, "port": port, "ERROR": str(e)})
            return {
                "ip": ip,
                "status": "command_error",
                "service": "SSL Certificate Check",
            }

        if "errno=60" in stderr_output:
            await logger.error(
                {
                    "ip": ip,
                    "port": port,
                    "ERROR": "Connection timed out",
                    "detail": stderr_output,
                }
            )
            return {"ip": ip, "status": "connection_timeout", "service": service}

        elif "unexpected eof" in stderr_output:
            pass

        elif process.returncode != 0:
            await logger.error(
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
                not_before_date = datetime.datetime.strptime(
                    not_before_str, date_format
                )
                not_after_date = datetime.datetime.strptime(not_after_str, date_format)
            except ValueError as e:
                await logger.error(
                    {
                        "ip": ip,
                        "ERROR": "Failed to parse the dates",
                        "exception": str(e),
                    }
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
                    "status": "recent_issued",
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
            await logger.error({"ip": ip, "ERROR": "Certificate dates not found"})
            return {
                "ip": ip,
                "status": "date_info_missing",
                "service": "SSL Certificate Check",
            }


async def notify_slack(message):
    try:
        async with ClientSession() as session:
            await asyncio.wait_for(
                session.post(SLACK_WEBHOOK_URL, json={"text": message}), timeout=TIMEOUT
            )
    except asyncio.TimeoutError:
        await logger.error({"ERROR": "Connection to Slack notification timed out"})


async def update_statsd(metric):
    try:
        async with statsd_client:
            await asyncio.wait_for(statsd_client.gauge(metric, 1), timeout=TIMEOUT)
    except asyncio.TimeoutError:
        await logger.error({"ERROR": "StatsD update timed out"})


async def main():
    semaphore = asyncio.Semaphore(CONCURRENT_LIMIT)
    tasks = []

    with open(IP_FILE_PATH) as file:
        for line in file:
            ip = line.strip()
            tasks.append(check_certificate(ip, semaphore))

    results = await asyncio.gather(*tasks)

    for result in results:
        if not result:
            continue

        if result["status"] == "expired":
            await logger.error(
                {
                    "ip": result["ip"],
                    "port": result["port"],
                    "status": "Certificate expired",
                }
            )
            await notify_slack(
                f"URGENT: Certificate for {result['ip']}:{result['port']} has expired."
            )
            await update_statsd(f"certs.{result['service']}.expired")

        elif result["status"] == "expiring_soon":
            await logger.warning(
                {
                    "ip": result["ip"],
                    "port": result["port"],
                    "status": "Certificate expiring soon",
                }
            )
            await notify_slack(
                f"Certificate for {result['ip']}:{result['port']} is expiring soon."
            )
            await update_statsd(f"certs.{result['service']}.expiring")

        elif result["status"] == "valid":
            await logger.info(
                {
                    "ip": result["ip"],
                    "port": result["port"],
                    "status": "Certificate is valid!",
                }
            )

        elif result["status"] == "recently_issued":
            await logger.info(
                {
                    "ip": result["ip"],
                    "port": result["port"],
                    "status": "Certificate recently issued",
                }
            )
            await notify_slack(
                f"Certificate for {result['ip']}:{result['port']} was recently issued."
            )


if __name__ == "__main__":
    asyncio.run(main())

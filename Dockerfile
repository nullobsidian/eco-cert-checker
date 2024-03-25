FROM ubuntu:18.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    cron=3.0pl1-128.1ubuntu1 \
    openssl=1.1.1-1ubuntu2.1~18.04.6 \
    python3=3.6.7-1~18.04 \
    python3-pip=9.0.1-2.3~ubuntu1.18.04.4 \
 && rm -rf /var/lib/apt/lists/*

COPY main.py /usr/src/app/main.py
COPY requirements.txt /usr/src/app/requirements.txt
COPY takehome_ip_addresses.txt /usr/src/app/takehome_ip_addresses.txt

RUN chmod +x /usr/src/app/main.py \
 && pip3 install --no-cache-dir -r /usr/src/app/requirements.txt

RUN echo "0 5 * * 2 python3 /usr/src/app/main.py" > /etc/cron.d/certificate_check \
 && chmod 0644 /etc/cron.d/certificate_check \
 && crontab /etc/cron.d/certificate_check \
 && touch /var/log/cron.log

CMD ["cron", "&&", "tail", "-f", "/var/log/cron.log"]

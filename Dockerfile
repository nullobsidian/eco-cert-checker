FROM ubuntu:18.04

# Environment variables
ARG SLACK_WEBOOK_URL
ARG STATSD_SERVER
ARG STATSD_PORT
ARG CONCURRENT_LIMIT
ARG EXPIRE_THRESHOLD_DAYS
ARG RECENT_THRESHOLD_DAYS
ARG TIMEOUT
ARG CRON_SCHEDULE
ARG IP_FILE_PATH
ARG CA_FILE_PATH

ENV SLACK_WEBOOK_URL=${SLACK_WEBOOK_URL} \
    STATSD_SERVER=${STATSD_SERVER} \
    STATSD_PORT=${STATSD_PORT} \
    CONCURRENT_LIMIT=${CONCURRENT_LIMIT} \
    EXPIRE_THRESHOLD_DAYS=${EXPIRE_THRESHOLD_DAYS} \
    RECENT_THRESHOLD_DAYS==${RECENT_THRESHOLD_DAYS} \
    TIMEOUT=${TIMEOUT} \
    CRON_SCHEDULE=${CRON_SCHEDULE} \
    IP_FILE_PATH=$(IP_FILE_PATH) \
    CA_FILE_PATH=$(CA_FILE_PATH)

RUN apt-get update && apt-get install -y --no-install-recommends \
    cron=3.0pl1-128.1ubuntu1.2 \
    openssl=1.1.1-1ubuntu2.1~18.04.23 \
    python3=3.6.7-1~18.04 \
    python3-pip=9.0.1-2.3~ubuntu1.18.04.8 \
 && rm -rf /var/lib/apt/lists/*

COPY main.py /usr/src/app/main.py
COPY requirements.txt /usr/src/app/requirements.txt
COPY takehome_ip_addresses.txt /usr/src/app/takehome_ip_addresses.txt

RUN chmod +x /usr/src/app/main.py \
 && pip3 install --no-cache-dir -r /usr/src/app/requirements.txt

RUN echo "${CRON_SCHEDULE} python3 /usr/src/app/main.py" > /etc/cron.d/certificate_check \
 && chmod 0644 /etc/cron.d/certificate_check \
 && crontab /etc/cron.d/certificate_check \
 && touch /var/log/cron.log

CMD ["cron", "&&", "tail", "-f", "/var/log/cron.log"]

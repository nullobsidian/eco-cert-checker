# eco-cert-checker
![SSL Certificate Check](misc/ssl.png)

## Overview

Eco-Cert-Checker is a versatile tool designed to bolster network security by facilitating the asynchronous verification of SSL/TLS certificates for a list of IP addresses, sends notifications and sends updates to metric server. This capability is crucial for maintaining the security and reliability of SSL/TLS certificates, essential components of secure network communications.

Tthis script serves as a core component of the eco-cert-checker suite, offering efficient and concurrent checks of SSL/TLS certificate validity. Utilizing the asyncio library, it manages asynchronous operations effectively, with the check_certificate function at its heart, ensuring thorough and reliable verification processes.

Deployment through an automated cron job, allowing for regular, scheduled certificate checks without the need for manual oversight. This continuous monitoring and validation mechanism significantly enhances network security protocols.

Designed with flexibility in mind, the tool's deployment is compatible with AWS environments, leveraging containerization with Docker Compose and infrastructure as code principles via Terraform. This deployment strategy highlights the tool's adaptability and scalability, aligning with modern DevOps practices for secure and efficient network management.

## Project Structure

```txt
/eco-cert-checker
│
├── terraform/
│   ├── main.tf                  # Terraform main configuration file
│   └── variables.tf             # Terraform variables definition file
│
├── tests/
│   ├── check_certificate.py     # Python script for checking SSL/TLS certificate status
│   └── unit_test.py             # Python script containing unit tests for the project
│
├── compose.yaml                 # Docker Compose file for defining and running multi-container Docker applications
├── .gitignore                   # Specifies intentionally untracked files to ignore
├── Dockerfile                   # Dockerfile to build the Docker image for the project
├── main.py                      # Main Python script for certificate verification
├── requirements.txt             # Lists dependencies to be installed
└── takehome_ip_addresses.txt    # Contains IP addresses for SSL/TLS certificate verification

```

### Key Components
- `main.py`: The core script of the project, it utilizes asynchronous programming to check SSL/TLS certificates for a predefined list of IP addresses. It includes functionality for logging, notifying Slack channels, and updating StatsD gauges based on the certificate status.
- `Dockerfile` and `compose.yaml`: These files are used for containerizing the application, allowing it to be run in isolated environments. The Dockerfile defines the steps for building the project's Docker image, while using orchestration `compose.yaml` to deploy into any environment.
- `tests/` directory: Contains `unit_test.py` and `check_certificate.py`. `unit_test.py` includes unit tests to verify the functionality of the SSL/TLS certificate checking process, ensuring it correctly identifies certificate validity and expiration. `check_certificate.py` contains the logic for checking the certificate status of a given IP address by making a synchronous OpenSSL connection.
- `terraform/` directory: Contains `main.tf` and `variables.tf` are part of the infrastructure as code (IaC) setup using Terraform. These files define the cloud resources required for the project.
- `takehome_ip_addresses.txt`: This text file contains a list of IP addresses. The main.py script reads from this file to determine which IP addresses to check for SSL/TLS certificate validity​​.

## Getting Started
To get started with the Eco-Cert-Checker, ensure Docker and Docker Compose are installed on your system. Then, follow these steps:

1. Clone the repository to your local machine.
2. Navigate to the project directory.
3. Build the Docker container with `docker-compose build`.
4. Run the application using `docker-compose up`.

## Dependencies
The project's dependencies are listed in the `requirements.txt` file. They will be automatically installed when building the Docker container.

For local development, you can install the dependencies using:

```bash
pip install -r requirements.txt
```
## Environment Variables

### Dockerfile and Docker Compose

| Variable Name           | Description                                                         |
|-------------------------|---------------------------------------------------------------------|
| `SLACK_WEBOOK_URL`      | URL for Slack webhook integration.                                  |
| `STATSD_SERVER`         | Hostname or IP address of the StatsD server for metrics.            |
| `STATSD_PORT`           | Port number for the StatsD server.                                  |
| `CONCURRENT_LIMIT`      | Maximum number of concurrent SSL certificate checks.                |
| `EXPIRE_THRESHOLD_DAYS` | Number of days before expiration to start alerting on certificates. |
| `RECENT_THRESHOLD_DAYS` | Threshold for considering a certificate as recently issued.         |
| `TIMEOUT`               | Timeout duration for SSL certificate checks.                        |
| `CRON_SCHEDULE`         | Schedule for the cron job that triggers SSL certificate checks.     |
| `IP_FILE_PATH`          | Path to the file containing IP addresses for SSL checks.            |
| `CA_FILE_PATH`          | (Optional) Path to a custom CA certificate file.                    |

### Terraform

| Variable Name    | Description                                                                   | Type   | Default Value |
|------------------|-------------------------------------------------------------------------------|--------|---------------|
| `instance_user`  | The default user for the EC2 instance.                                        | string | `ubuntu`      |
| `cron_schedule`  | Schedule for the cron job schedule that tiggers a pull changes from Github    | string | `0 17 * * *`  |
| `instance_type`  | The type of instance to launch.                                               | string | `t2.micro`    |

provider "aws" {
  region = "us-east-1"
}

data "aws_secretsmanager_secret_version" "ssh_key" {
  secret_id = "sa_gh_key"
}

resource "aws_instance" "ssl_instance" {
  ami           = "ami-055744c75048d8296" # Ubuntu Server 18.04 LTS
  instance_type = "t2.micro"

  vpc_security_group_ids = [aws_security_group.ssl_vm_sg.id]

  user_data = <<-EOF
                #!/bin/bash
                # Update and install necessary packages
                apt-get update -y
                apt-get install -y git docker.io
                systemctl start docker
                systemctl enable docker
                curl -L "https://github.com/docker/compose/releases/download/2.24.6/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
                chmod +x /usr/local/bin/docker-compose

                # Fetch SSH key AWS Secrets Manager and store temporarily
                echo '${data.aws_secretsmanager_secret_version.ssh_key.secret_string}' > /tmp/id_rsa
                chmod 600 /tmp/id_rsa

                # Set up SSH for GitHub
                mkdir -p /home/${var.instance_user}/.ssh
                chmod 700 /home/${var.instance_user}/.ssh
                mv /tmp/id_rsa /home/${var.instance_user}/.ssh/id_rsa
                chown -R ${var.instance_user}:${var.instance_user} /home/${var.instance_user}/.ssh
                echo -e "Host github.com\n\tStrictHostKeyChecking no\n" >> /home/${var.instance_user}/.ssh/config

                # Clone repository
                git clone git@github.com:nullobsidian/eco-cert-checker.git /app
                cd /app
                docker-compose up -d

                # Cron job to pull changes and restart the application
                echo "${var.cron_schedule} cd /app && git pull && docker-compose up -d" > /etc/cron.d/app_update
              EOF

  tags = {
    Name = "DockerComposeApp"
  }
}

resource "aws_security_group" "ssl_vm_sg" {
  name        = "ssl_vm_security_group"
  description = "Allow SSH and HTTP traffic to the app"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

variable "instance_user" {
  description = "The default user for the EC2 instance"
  type        = string
  default     = "ubuntu"
}

variable "cron_schedule" {
  description = "Cron job schedule 'minute hour * * *' format. Defaults to '0 17 * * *' (5 PM daily)"
  type        = string
  default     = "0 17 * * *"
}

variable "instance_type" {
  description = "The type of instance to launch."
  type        = string
  default     = "t2.micro"
}

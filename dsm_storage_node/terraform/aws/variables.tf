# DSM Storage Nodes — Terraform Variables (Multi-Region)
#
# 6 nodes across 3 regions: us-east-1, eu-west-1, ap-southeast-1
# Region/node distribution is configured in main.tf module calls.

variable "instance_type" {
  description = "EC2 instance type (t3.small = 2 vCPU, 2GB RAM — runs Rust binary + PostgreSQL)"
  type        = string
  default     = "t3.small"
}

variable "volume_size_gb" {
  description = "Root EBS volume size in GB (gp3). Index-only storage; 20GB sufficient for beta."
  type        = number
  default     = 20
}

variable "ssh_public_key" {
  description = "SSH public key for EC2 access (e.g. contents of ~/.ssh/id_ed25519.pub)"
  type        = string
}

variable "allowed_ssh_cidr" {
  description = "The one CIDR block allowed SSH access, e.g. 1.2.3.4/32. No default: SSH open to everyone is never assumed."
  type        = string

  validation {
    condition     = can(cidrhost(var.allowed_ssh_cidr, 0)) && !contains(["0.0.0.0/0", "::/0"], var.allowed_ssh_cidr)
    error_message = "allowed_ssh_cidr must be a CIDR block narrower than the whole internet (e.g. 1.2.3.4/32)."
  }
}

variable "project_tag" {
  description = "Tag applied to all resources for identification and cost tracking"
  type        = string
  default     = "dsm-storage"
}

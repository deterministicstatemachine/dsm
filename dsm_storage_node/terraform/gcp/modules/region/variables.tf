variable "region" { type = string }
variable "gcp_project" { type = string }
variable "node_count" { type = number }

variable "machine_type" {
  type    = string
  default = "e2-small"
}

variable "disk_size_gb" {
  type    = number
  default = 20
}

variable "ssh_public_key" { type = string }

variable "ssh_username" {
  type    = string
  default = "ubuntu"
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
  type    = string
  default = "dsm-storage"
}

variable "global_node_offset" {
  type    = number
  default = 0
}

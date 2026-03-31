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
  type    = string
  default = "0.0.0.0/0"
}

variable "project_tag" {
  type    = string
  default = "dsm-storage"
}

variable "global_node_offset" {
  type    = number
  default = 0
}

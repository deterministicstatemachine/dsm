# DSM Storage Region Module — Variables

variable "node_count" {
  description = "Number of storage nodes in this region"
  type        = number
}

variable "instance_type" {
  type    = string
  default = "t3.small"
}

variable "volume_size_gb" {
  type    = number
  default = 20
}

variable "ssh_public_key" {
  type = string
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
  description = "Offset for node numbering (e.g. region 1 starts at 0, region 2 at 2)"
  type        = number
  default     = 0
}

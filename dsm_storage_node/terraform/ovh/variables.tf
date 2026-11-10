variable "region" {
  description = "The OpenStack region the nodes run in (OVHcloud: BHS5, GRA11, SBG5, ...)."
  type        = string
  default     = "BHS5"
}
variable "flavor_name" {
  description = "The instance flavor: d2-4 is 2 vCPU, 4 GB, 50 GB local disk."
  type        = string
  default     = "d2-4"
}
variable "image_name" {
  type    = string
  default = "Ubuntu 22.04"
}
variable "ssh_public_key" { type = string }
variable "allowed_ssh_cidr" {
  description = "The one CIDR block allowed SSH access, e.g. 1.2.3.4/32. No default: SSH open to everyone is never assumed."
  type        = string
  validation {
    condition     = can(cidrhost(var.allowed_ssh_cidr, 0)) && !contains(["0.0.0.0/0", "::/0"], var.allowed_ssh_cidr)
    error_message = "allowed_ssh_cidr must be a CIDR block narrower than the whole internet (e.g. 1.2.3.4/32)."
  }
}
variable "private_node_count" {
  description = "Members of the owner's private fleet (0 until it is wanted)."
  type        = number
  default     = 0
}
variable "project_tag" {
  type    = string
  default = "dsm-storage"
}

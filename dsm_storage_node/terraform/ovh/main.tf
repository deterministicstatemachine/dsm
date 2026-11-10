terraform {
  required_version = ">= 1.5"
  required_providers {
    openstack = {
      source  = "terraform-provider-openstack/openstack"
      version = "~> 2.1"
    }
  }
}

# OVHcloud Public Cloud is OpenStack. The provider reads the project's
# OpenStack RC file from the environment (OS_AUTH_URL, OS_TENANT_ID,
# OS_USERNAME, OS_PASSWORD, OS_REGION_NAME); deploy/provision_ovh.sh exports
# it. Nothing here names the project or its user.
provider "openstack" {
  region = var.region
}

resource "openstack_compute_keypair_v2" "deploy" {
  name       = "${var.project_tag}-deploy"
  public_key = var.ssh_public_key
}

# A fresh OVHcloud project has a quota of ZERO security groups and rules, so
# the nodes sit in the project's `default` group, which lets everything in
# and out. What restricts them is the host firewall each node's bootstrap
# installs (firewall.sh.tftpl): SSH from `allowed_ssh_cidr` alone, the
# storage API from anywhere, nothing else inbound (SA-151).
locals {
  user_data = join("\n", [
    file("${path.module}/../gcp/user_data.sh"),
    templatefile("${path.module}/firewall.sh.tftpl", { allowed_ssh_cidr = var.allowed_ssh_cidr }),
  ])
}

# The beta fleet: five members in one region, quorum 3 of 5, so every
# quorum-bound operation stays inside one datacentre (as terraform/gcp says).
module "beta" {
  source = "./modules/fleet"

  name_prefix    = "dsm-storage-node"
  node_count     = 5
  flavor_name    = var.flavor_name
  image_name     = var.image_name
  key_pair       = openstack_compute_keypair_v2.deploy.name
  security_group = "default"
  user_data      = local.user_data
  project_tag    = var.project_tag
  fleet          = "beta"
}

# The owner's private fleet, a second set of its own for testing updates
# before they reach beta (owner, 2026-11-05). Zero members until it is
# wanted; raising `private_node_count` adds them without touching beta.
module "private" {
  source = "./modules/fleet"

  name_prefix    = "dsm-private-node"
  node_count     = var.private_node_count
  flavor_name    = var.flavor_name
  image_name     = var.image_name
  key_pair       = openstack_compute_keypair_v2.deploy.name
  security_group = "default"
  user_data      = local.user_data
  project_tag    = var.project_tag
  fleet          = "private"
}

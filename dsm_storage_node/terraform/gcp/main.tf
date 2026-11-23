terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.gcp_project
  region  = "us-central1"
}

# This configuration is FIVE nodes in one region (the former beta fleet; the
# beta fleet runs from terraform/ovh). A write is final once its route chain
# has the leader's link and two more, and every settle waits on that, so the
# members sit next to each other rather than across continents: an
# intercontinental hop would be on the critical path of every write the rig
# makes.
module "us_central1" {
  source = "./modules/region"

  region             = "us-central1"
  gcp_project        = var.gcp_project
  node_count         = 5
  machine_type       = var.machine_type
  disk_size_gb       = var.disk_size_gb
  ssh_public_key     = var.ssh_public_key
  ssh_username       = var.ssh_username
  allowed_ssh_cidr   = var.allowed_ssh_cidr
  project_tag        = var.project_tag
  global_node_offset = 0
}

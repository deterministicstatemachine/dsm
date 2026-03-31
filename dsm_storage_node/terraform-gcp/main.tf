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
  alias   = "us_east1"
  project = var.gcp_project
  region  = "us-east1"
}

provider "google" {
  alias   = "europe_west1"
  project = var.gcp_project
  region  = "europe-west1"
}

provider "google" {
  alias   = "asia_southeast1"
  project = var.gcp_project
  region  = "asia-southeast1"
}

module "us_east1" {
  source    = "./modules/region"
  providers = { google = google.us_east1 }

  region             = "us-east1"
  gcp_project        = var.gcp_project
  node_count         = 2
  machine_type       = var.machine_type
  disk_size_gb       = var.disk_size_gb
  ssh_public_key     = var.ssh_public_key
  ssh_username       = var.ssh_username
  allowed_ssh_cidr   = var.allowed_ssh_cidr
  project_tag        = var.project_tag
  global_node_offset = 0
}

module "europe_west1" {
  source    = "./modules/region"
  providers = { google = google.europe_west1 }

  region             = "europe-west1"
  gcp_project        = var.gcp_project
  node_count         = 2
  machine_type       = var.machine_type
  disk_size_gb       = var.disk_size_gb
  ssh_public_key     = var.ssh_public_key
  ssh_username       = var.ssh_username
  allowed_ssh_cidr   = var.allowed_ssh_cidr
  project_tag        = var.project_tag
  global_node_offset = 2
}

module "asia_southeast1" {
  source    = "./modules/region"
  providers = { google = google.asia_southeast1 }

  region             = "asia-southeast1"
  gcp_project        = var.gcp_project
  node_count         = 2
  machine_type       = var.machine_type
  disk_size_gb       = var.disk_size_gb
  ssh_public_key     = var.ssh_public_key
  ssh_username       = var.ssh_username
  allowed_ssh_cidr   = var.allowed_ssh_cidr
  project_tag        = var.project_tag
  global_node_offset = 4
}

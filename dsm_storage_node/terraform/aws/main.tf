# DSM Storage Nodes — Multi-Region Terraform Configuration
#
# Provisions 6 independent EC2 instances across 3 AWS regions for geographic
# distribution (2 nodes per region). Storage nodes are not a consensus system —
# consensus, no leaders, no shared state. Each node independently stores bytes,
# mirrors ByteCommit chains, and enforces byte accounting.
#
# Regions: us-east-1 (N. Virginia), eu-west-1 (Ireland), ap-southeast-1 (Singapore)
#
# Usage:
#   terraform init
#   terraform plan -var="ssh_public_key=$(cat ~/.ssh/id_ed25519.pub)"
#   terraform apply -var="ssh_public_key=$(cat ~/.ssh/id_ed25519.pub)"

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# --- Provider aliases (one per region) ---
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}

provider "aws" {
  alias  = "eu_west_1"
  region = "eu-west-1"
}

provider "aws" {
  alias  = "ap_southeast_1"
  region = "ap-southeast-1"
}

# --- Region modules (2 nodes each = 6 total) ---

module "us_east_1" {
  source = "./modules/region"
  providers = {
    aws = aws.us_east_1
  }

  node_count         = 2
  instance_type      = var.instance_type
  volume_size_gb     = var.volume_size_gb
  ssh_public_key     = var.ssh_public_key
  allowed_ssh_cidr   = var.allowed_ssh_cidr
  project_tag        = var.project_tag
  global_node_offset = 0
}

module "eu_west_1" {
  source = "./modules/region"
  providers = {
    aws = aws.eu_west_1
  }

  node_count         = 2
  instance_type      = var.instance_type
  volume_size_gb     = var.volume_size_gb
  ssh_public_key     = var.ssh_public_key
  allowed_ssh_cidr   = var.allowed_ssh_cidr
  project_tag        = var.project_tag
  global_node_offset = 2
}

module "ap_southeast_1" {
  source = "./modules/region"
  providers = {
    aws = aws.ap_southeast_1
  }

  node_count         = 2
  instance_type      = var.instance_type
  volume_size_gb     = var.volume_size_gb
  ssh_public_key     = var.ssh_public_key
  allowed_ssh_cidr   = var.allowed_ssh_cidr
  project_tag        = var.project_tag
  global_node_offset = 4
}

# DSM Storage Region Module
#
# Creates N storage node instances in a single region with their own
# security group and key pair.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

data "aws_region" "current" {}

# SSH key pair (per-region)
resource "aws_key_pair" "dsm" {
  key_name   = "${var.project_tag}-key-${data.aws_region.current.name}"
  public_key = var.ssh_public_key

  tags = {
    Project = var.project_tag
  }
}

# Ubuntu 22.04 LTS AMI (per-region — AMI IDs differ by region)
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

# Default VPC in this region
data "aws_vpc" "default" {
  default = true
}

# Security group (per-region)
resource "aws_security_group" "dsm_storage" {
  name        = "${var.project_tag}-sg-${data.aws_region.current.name}"
  description = "DSM storage node - API, metrics, SSH, inter-node gossip"
  vpc_id      = data.aws_vpc.default.id

  # Storage node API (HTTPS) — clients and inter-node gossip
  ingress {
    description = "Storage node API (HTTPS)"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Prometheus metrics
  ingress {
    description = "Prometheus metrics"
    from_port   = 9090
    to_port     = 9090
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # SSH access (restricted)
  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ssh_cidr]
  }

  # All outbound traffic
  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "${var.project_tag}-sg-${data.aws_region.current.name}"
    Project = var.project_tag
  }
}

# N storage node instances in this region
resource "aws_instance" "dsm_node" {
  count = var.node_count

  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  key_name               = aws_key_pair.dsm.key_name
  vpc_security_group_ids = [aws_security_group.dsm_storage.id]

  user_data = file("${path.module}/../../user_data.sh")

  root_block_device {
    volume_size           = var.volume_size_gb
    volume_type           = "gp3"
    delete_on_termination = true
  }

  tags = {
    Name    = "dsm-storage-node-${var.global_node_offset + count.index + 1}"
    Project = var.project_tag
    Role    = "storage-node"
    NodeIdx = tostring(var.global_node_offset + count.index + 1)
    Region  = data.aws_region.current.name
  }
}

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

resource "google_compute_firewall" "dsm_api" {
  name    = "${var.project_tag}-allow-api-${var.region}"
  network = "default"
  project = var.gcp_project

  allow {
    protocol = "tcp"
    ports    = ["8080"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["dsm-storage-node"]
}

resource "google_compute_firewall" "dsm_ssh" {
  name    = "${var.project_tag}-allow-ssh-${var.region}"
  network = "default"
  project = var.gcp_project

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = [var.allowed_ssh_cidr]
  target_tags   = ["dsm-storage-node"]
}

# Each node's PostgreSQL — every byte it ever acknowledged — lives on its boot
# disk, and a node never loses stored bytes (storage spec §3). An edited
# bootstrap never replaces a running node (`ignore_changes`), nothing in this
# module can destroy one (`prevent_destroy`: a plan that would is refused, and
# retiring a node is a deliberate edit after its handover, storage spec
# §12.5), and the boot disk outlives the VM if the VM is ever deleted
# (`auto_delete = false`).
resource "google_compute_instance" "dsm_node" {
  count        = var.node_count
  name         = "dsm-storage-node-${var.global_node_offset + count.index + 1}"
  machine_type = var.machine_type
  zone         = "${var.region}-b"
  project      = var.gcp_project
  tags         = ["dsm-storage-node"]

  boot_disk {
    auto_delete = false
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2204-lts"
      size  = var.disk_size_gb
      type  = "pd-balanced"
    }
  }

  network_interface {
    network = "default"
    access_config {}
  }

  metadata = {
    ssh-keys = "${var.ssh_username}:${var.ssh_public_key}"
  }

  metadata_startup_script = file("${path.module}/../../user_data.sh")

  labels = {
    project  = var.project_tag
    role     = "storage-node"
    node-idx = tostring(var.global_node_offset + count.index + 1)
    region   = var.region
  }

  lifecycle {
    ignore_changes  = [metadata_startup_script]
    prevent_destroy = true
  }
}

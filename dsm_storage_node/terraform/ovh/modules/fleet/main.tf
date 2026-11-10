terraform {
  required_providers {
    openstack = {
      source  = "terraform-provider-openstack/openstack"
      version = "~> 2.1"
    }
  }
}

# Each node's PostgreSQL — every byte it ever acknowledged — lives on the
# instance's local disk, and a node never loses stored bytes (storage spec
# §3). An edited bootstrap never replaces a running node (`ignore_changes`),
# and nothing in this module can destroy one (`prevent_destroy`: a plan that
# would is refused, and retiring a node is a deliberate edit after its
# handover, storage spec §12.5). On OpenStack the local disk dies with the
# instance, so that refusal is the only thing between a plan and the data.
# The host firewall is part of the bootstrap (terraform/ovh/firewall.sh.tftpl).
resource "openstack_compute_instance_v2" "dsm_node" {
  count           = var.node_count
  name            = "${var.name_prefix}-${count.index + 1}"
  image_name      = var.image_name
  flavor_name     = var.flavor_name
  key_pair        = var.key_pair
  security_groups = [var.security_group]

  network {
    name = "Ext-Net"
  }

  user_data = var.user_data

  metadata = {
    project  = var.project_tag
    role     = "storage-node"
    fleet    = var.fleet
    node-idx = tostring(count.index + 1)
  }

  lifecycle {
    ignore_changes  = [user_data, image_name]
    prevent_destroy = true
  }
}

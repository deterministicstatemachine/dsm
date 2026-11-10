output "node_ips" {
  value = openstack_compute_instance_v2.dsm_node[*].access_ip_v4
}
output "node_names" {
  value = openstack_compute_instance_v2.dsm_node[*].name
}

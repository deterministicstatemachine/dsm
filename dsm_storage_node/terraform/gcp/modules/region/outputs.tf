output "node_ips" {
  value = google_compute_instance.dsm_node[*].network_interface[0].access_config[0].nat_ip
}
output "node_names" {
  value = google_compute_instance.dsm_node[*].name
}
output "region" { value = var.region }

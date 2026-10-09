output "all_node_ips" { value = module.us_central1.node_ips }

output "region_summary" {
  value = {
    "us-central1" = module.us_central1.node_ips
  }
}

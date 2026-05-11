locals {
  all_ips = concat(
    module.us_east1.node_ips,
    module.europe_west1.node_ips,
    module.asia_southeast1.node_ips
  )
}

output "all_node_ips" { value = local.all_ips }
output "us_east1_ips" { value = module.us_east1.node_ips }
output "europe_west1_ips" { value = module.europe_west1.node_ips }
output "asia_southeast1_ips" { value = module.asia_southeast1.node_ips }

output "region_summary" {
  value = {
    "us-east1"        = module.us_east1.node_ips
    "europe-west1"    = module.europe_west1.node_ips
    "asia-southeast1" = module.asia_southeast1.node_ips
  }
}

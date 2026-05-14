# DSM Storage Nodes — Multi-Region Outputs

locals {
  all_ips = concat(
    module.us_east_1.node_ips,
    module.eu_west_1.node_ips,
    module.ap_southeast_1.node_ips
  )
}

output "all_node_ips" {
  description = "All storage node public IPs (ordered: us-east-1, eu-west-1, ap-southeast-1)"
  value       = local.all_ips
}

output "us_east_1_ips" {
  description = "Node IPs in us-east-1 (N. Virginia)"
  value       = module.us_east_1.node_ips
}

output "eu_west_1_ips" {
  description = "Node IPs in eu-west-1 (Ireland)"
  value       = module.eu_west_1.node_ips
}

output "ap_southeast_1_ips" {
  description = "Node IPs in ap-southeast-1 (Singapore)"
  value       = module.ap_southeast_1.node_ips
}

output "region_summary" {
  description = "Node distribution by region"
  value = {
    "us-east-1"      = module.us_east_1.node_ips
    "eu-west-1"      = module.eu_west_1.node_ips
    "ap-southeast-1" = module.ap_southeast_1.node_ips
  }
}

output "generate_configs_command" {
  description = "Run this to generate per-node deploy bundles"
  value       = "cd ../deploy && ./generate_node_configs.sh ${join(" ", local.all_ips)}"
}

output "push_and_start_command" {
  description = "Run this to deploy and start all nodes"
  value       = "cd ../deploy && ./push_and_start.sh ${join(" ", local.all_ips)}"
}

output "check_nodes_command" {
  description = "Run this to verify all nodes are healthy"
  value       = "cd ../deploy && ./check_nodes.sh ${join(" ", local.all_ips)}"
}

output "ssh_example" {
  description = "Example SSH command to connect to first node (us-east-1)"
  value       = "ssh ubuntu@${length(local.all_ips) > 0 ? local.all_ips[0] : "N/A"}"
}

output "cost_estimate" {
  description = "Estimated monthly cost"
  value       = "6x ${var.instance_type} + ${var.volume_size_gb}GB gp3 each across 3 regions (~$90/month for t3.small)"
}

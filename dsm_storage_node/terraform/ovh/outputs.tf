output "all_node_ips" { value = module.beta.node_ips }
output "private_node_ips" { value = module.private.node_ips }

output "fleet_summary" {
  value = {
    beta    = module.beta.node_ips
    private = module.private.node_ips
  }
}

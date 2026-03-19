# DSM Storage Region Module — Outputs

output "node_ips" {
  description = "Public IP addresses of storage nodes in this region"
  value       = aws_instance.dsm_node[*].public_ip
}

output "node_ids" {
  description = "EC2 instance IDs in this region"
  value       = aws_instance.dsm_node[*].id
}

output "region" {
  description = "AWS region for these nodes"
  value       = data.aws_region.current.name
}

#!/bin/bash

# DSM Storage Node - Monitoring Setup
echo "📊 Setting up monitoring for DSM Storage Node..."

# Create monitoring directory
mkdir -p ./monitoring

# Create basic health check script
cat > ./monitoring/health_check.sh << 'HEALTH'
#!/bin/bash

# DSM Storage Node Health Check
API_PORT=${DSM_API_PORT:-8080}
HEALTH_ENDPOINT="http://127.0.0.1:${API_PORT}/health"

# Check if node is responding
if curl -f -s "${HEALTH_ENDPOINT}" > /dev/null; then
    echo "✅ DSM Storage Node is healthy"
    exit 0
else
    echo "❌ DSM Storage Node is not responding"
    exit 1
fi
HEALTH

chmod +x ./monitoring/health_check.sh

# Create log rotation configuration
cat > ./monitoring/logrotate.conf << 'LOGROTATE'
# DSM Storage Node Log Rotation
./logs/secure/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 640 $(whoami) $(whoami)
    postrotate
        # Send SIGHUP to dsm process to reopen log files
        pkill -HUP dsm_storage_node || true
    endscript
}
LOGROTATE

echo "Monitoring setup complete!"
echo "Add to crontab for health checks:"
echo "*/5 * * * * /path/to/dsm/monitoring/health_check.sh"

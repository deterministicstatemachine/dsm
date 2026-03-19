-- Clockless replay table: no wall-clock markers
CREATE TABLE IF NOT EXISTS inbox_receipts (
  device_id TEXT NOT NULL,
  message_id TEXT NOT NULL,
  PRIMARY KEY (device_id, message_id)
);
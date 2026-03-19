-- Clockless inbox spool (no wall-clock markers)
CREATE TABLE IF NOT EXISTS inbox_spool (
  id         BIGSERIAL PRIMARY KEY,
  device_id  TEXT NOT NULL,
  message_id TEXT NOT NULL UNIQUE,
  envelope   BYTEA NOT NULL,
  acked      BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_inbox_spool_device_acked
  ON inbox_spool(device_id, acked, id);

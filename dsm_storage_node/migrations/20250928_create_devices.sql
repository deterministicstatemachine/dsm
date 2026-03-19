CREATE TABLE IF NOT EXISTS devices (
  device_id   TEXT PRIMARY KEY,
  genesis_hash BYTEA NOT NULL,
  pubkey      BYTEA NOT NULL,
  token_hash  BYTEA NOT NULL,
  revoked     BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_devices_revoked ON devices(revoked);
-- Add sequence numbers and expiration to inbox_spool
-- Clockless design: sequence numbers are per-device monotonic counters
-- Expiration uses iteration-based expiration (no wall clocks)

ALTER TABLE inbox_spool
ADD COLUMN IF NOT EXISTS seq_num BIGINT NOT NULL DEFAULT 0,
ADD COLUMN IF NOT EXISTS expires_at_iter BIGINT;

-- Create index for efficient sequence-based retrieval
CREATE INDEX IF NOT EXISTS idx_inbox_spool_device_seq
  ON inbox_spool(device_id, seq_num);

-- Create index for expiration cleanup
CREATE INDEX IF NOT EXISTS idx_inbox_spool_expires
  ON inbox_spool(expires_at_iter) WHERE expires_at_iter IS NOT NULL;

-- Update existing rows to have sequence numbers (backfill)
-- This assigns sequence numbers based on insertion order
UPDATE inbox_spool
SET seq_num = sub.row_num
FROM (
  SELECT id, ROW_NUMBER() OVER (PARTITION BY device_id ORDER BY id) as row_num
  FROM inbox_spool
) sub
WHERE inbox_spool.id = sub.id;
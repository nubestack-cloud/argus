DELETE FROM enrollment_tokens WHERE ttl_class = 'F';
ALTER TABLE enrollment_tokens
  DROP COLUMN revoked_at,
  DROP COLUMN auto_accept,
  DROP COLUMN name;
ALTER TABLE enrollment_tokens DROP CONSTRAINT enrollment_tokens_ttl_class_check;
ALTER TABLE enrollment_tokens ADD CONSTRAINT enrollment_tokens_ttl_class_check CHECK (ttl_class IN ('A', 'B', 'C'));

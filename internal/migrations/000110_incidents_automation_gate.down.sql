ALTER TABLE incidents DROP CONSTRAINT IF EXISTS incidents_automation_gate_pair;
ALTER TABLE incidents DROP COLUMN IF EXISTS automation_gate;
ALTER TABLE incidents DROP COLUMN IF EXISTS automation_gate_reason;
ALTER TABLE incidents DROP COLUMN IF EXISTS automation_gate_at;

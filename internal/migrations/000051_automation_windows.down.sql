-- Reversible, and the direction is worth naming: dropping this removes every
-- configured freeze, so automation becomes unrestricted by time again. That is a
-- loosening, not a tightening — the opposite of what a rollback usually is here.
DROP TABLE IF EXISTS automation_windows;

-- Reverses 000099. Dropping the table takes its index and both policies with
-- it, matching 000037's own down migration precedent.
--
-- Lossy, stated rather than hidden: every recorded tool call's content is
-- discarded. Nothing else depends on these rows (no foreign key points at
-- them), and internal/llm's value-agreement check reads "unchecked" rather
-- than erroring when this table has nothing for a citation — the correct
-- trade for a rollback, not round-tripping data.
DROP TABLE mcp_tool_call_content;

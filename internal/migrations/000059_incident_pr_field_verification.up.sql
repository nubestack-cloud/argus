-- Closes BUGS.md 77 / lld/08-remediation-contracts.md §12.8: ValidationSweeper
-- selected candidates by inner-joining remediation_executions, which the
-- pull-request route never writes, so a merged, synced fix reached Validating
-- and could never leave it. §12.8's fix is a fix-landed clock resolved PER
-- ROUTE: remediation_executions.executed_at for in-place (unchanged),
-- incidents.pr_merged_at (migration 000058, written by MergeSweeper, never
-- read before this) for pull-request.
--
-- The clock alone reopens the AwaitingMerge->Validating->Resolved exit, but
-- §12.8 also asks for the assertion to be at least as strong as the in-place
-- one: re-read the field the merged pull request changed and confirm it still
-- holds the value that was merged, rather than resolving on silence alone.
-- That needs the field path and expected value recorded at the moment the
-- pull request opens — gitops.ProposeFieldChange already computed and
-- verified both before cutting the branch, so this is not new information,
-- only the first time it survives past the response.
--
-- ON INCIDENTS, same reasoning migration 000058 already gives for pr_number/
-- pr_merged_at: a pull request can open via either approveByOpeningPullRequest
-- (an approved OpenPR recommendation) or handleOpenRepositoryChange (the
-- self-service route, which routinely runs with NO remediation_recommendations
-- row at all) — so the column recording what the request changed belongs on
-- the incident, which both routes always have, not on a recommendation row
-- one of them may never have written.
ALTER TABLE incidents ADD COLUMN pr_field_path text;
ALTER TABLE incidents ADD COLUMN pr_expected_value text;

-- No index: both are read by incident id (the primary key) for exactly one
-- row, same as pr_number/pr_merged_at.

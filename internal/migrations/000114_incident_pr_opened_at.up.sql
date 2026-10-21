-- incidents.pr_opened_at — when the CURRENT pull request for this incident was
-- opened.
--
-- The gap this closes, measured on a live PR-route incident: while an incident
-- sits in AwaitingMerge, the product is explicitly waiting for a human to go and
-- merge something, and the one thing it could not tell them was how long it had
-- been waiting. changes.go's own header said so in as many words — "there is no
-- column recording when a pull request was OPENED" — and used that absence to
-- justify listing merged pull requests only, because pr_merged_at was the only
-- timestamp either route reliably wrote.
--
-- ON INCIDENTS, for the same reason migrations 000058/000059/000060/000089 give
-- for every other pr_* column: a pull request can open via either
-- approveByOpeningPullRequest (approvals.go) or the self-service
-- handleOpenRepositoryChange route (repository_change.go), and the incident is
-- the one row both are guaranteed to have in hand.
--
-- IT DESCRIBES THE CURRENT PULL REQUEST, NOT THE FIRST ONE. Both writers null
-- pr_merged_at/pr_closed_unmerged_at/pr_rejection_reason when they record a new
-- pr_number, because an incident whose first pull request was closed unmerged
-- returns to AwaitingApproval and can open a second — and incidentPullRequestRecord
-- reports one row keyed only by incident id, so a stale column from the PREVIOUS
-- pull request renders as a fact about the current one. pr_opened_at is written
-- unconditionally in that same UPDATE and therefore follows the same rule: it is
-- always the open-time of the pull request pr_number names.
--
-- Nullable, because a pull request opened before this migration has no opened-at
-- of its own, and "opened by an earlier build" must stay distinguishable from
-- "not open". Clients render an absent value as absent — never as a zero, a dash
-- standing in for a duration, or an age computed from some other column.
ALTER TABLE incidents ADD COLUMN pr_opened_at timestamptz;

-- Backfill, and the reason it is not a guess.
--
-- approveByOpeningPullRequest records a `PullRequestOpened` timeline event whose
-- payload carries `pullRequestUrl` — the hub's own contemporaneous record of the
-- moment it opened that exact pull request. Matching that payload URL against
-- incidents.pr_url (migration 000089) identifies the event for the CURRENT pull
-- request specifically, rather than assuming the incident only ever had one, so
-- an incident whose second pull request is open does not inherit the first one's
-- timestamp — the precise failure the paragraph above exists to prevent.
--
-- Deliberately NOT backfilled by any looser rule. "The newest PullRequestOpened
-- event on this incident" would be right in every case in this database and
-- wrong the first time a re-proposal happened without a URL to key on, and an
-- incident's created_at / state-change time is not when a pull request opened.
-- Rows that cannot be matched exactly are left NULL, which every reader already
-- has to handle for pre-000089 pull requests anyway.
UPDATE incidents i
   SET pr_opened_at = t.occurred_at
  FROM (
        SELECT incident_id,
               payload->>'pullRequestUrl' AS url,
               max(occurred_at)           AS occurred_at
          FROM timeline_events
         WHERE event_type = 'PullRequestOpened'
           AND payload->>'pullRequestUrl' IS NOT NULL
         GROUP BY incident_id, payload->>'pullRequestUrl'
       ) t
 WHERE t.incident_id = i.id
   AND i.pr_url IS NOT NULL
   AND i.pr_url = t.url
   AND i.pr_number IS NOT NULL;

-- No index: read by incident id (the primary key) for exactly one row on the
-- detail page, and as a plain projection in the changes feed's bounded window
-- scan — same access shape as every other pr_* column.

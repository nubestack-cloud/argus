package api

// This file is BACKLOG.md "still open" #4's fix — the `AF1`/`DEPL-003`
// finding: a manifest rejected AT ADMISSION TIME never becomes a live
// object, so resolveRepoChangeTarget's ordinary object (loadIncidentObject,
// repository_change.go) has nothing real to search for — every incident this
// codebase can build one from anchors on the Argo Application/Flux
// Kustomization/HelmRelease that reported the failure instead
// (BACKLOG.md "still open" #3's fix, 2026-08-29, is what made that
// resolution correct in the first place: an Application has no owner of its
// own to walk up from). The Application's OWN manifest almost never lives
// inside the directory its spec.source.path points at, so the ordinary
// search over that directory legitimately finds nothing.
//
// Nothing about gitops.Locate/LocateIn needed to change to fix this —
// ObjectRef was always a plain kind/name/namespace tuple, never something
// read off a live object's own fields (see internal/gitops/identity.go's
// header). The only new work is populating one FROM SOMEWHERE ELSE: Argo's
// own sync-failure message (forwarded verbatim onto the incident's finding
// by internal/agent/syncfailure.go's checkArgoSyncFailed) names the kind and
// name of the object the API server actually refused. This file reads that
// message back off the SAME finding loadIncidentObject already resolved the
// Application onto, parses it (gitops.ParseAdmissionRejectionObject), and
// hands the result to the exact same locateObjectFile the ordinary path
// uses — same clone, same LocateIn, same "refuse rather than guess" errors,
// scoped to the exact same spec.source.path. Nothing is duplicated; the
// search itself runs once per attempt, exactly as it always has.

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"argus/internal/gitops"
	"argus/internal/logging"
	"argus/internal/scm"
)

// locateObjectFileWithFallback is locateObjectFile, plus one more attempt
// when the ordinary search comes back empty AND the object being searched
// for is itself a GitOps controller object (gitops.IsControllerObject) — see
// this file's header for why that specific shape is the tell that there was
// never a live workload object to anchor on.
//
// The ordinary path always runs FIRST, unconditionally, and its result is
// returned as-is whenever it succeeds — an incident that (unusually) IS
// anchored on a literal copy of the Application's own manifest inside its
// own synced directory resolves the ordinary way, exactly as it does today.
// The fallback only ever runs after the ordinary search has already failed,
// which is why it changes nothing about that regression case: it is not
// consulted unless there is nothing else to go on.
func locateObjectFileWithFallback(ctx context.Context, tx pgx.Tx, incidentID, gvk string, provider scm.Provider, binding scm.Binding, repoURL, revision, sourceDir string, object gitops.ObjectRef) (discoveredFile, error) {
	found, err := locateObjectFile(ctx, provider, binding, repoURL, revision, sourceDir, object)
	if err == nil {
		return found, nil
	}
	if !gitops.IsControllerObject(object) {
		return discoveredFile{}, err
	}

	kind, name, ok := findAdmissionRejectionIdentity(ctx, tx, incidentID, gvk, object.Namespace, object.Name)
	if !ok {
		// Nothing to fall back to — the ordinary refusal is the more
		// informative error (it names the Application/Kustomization/
		// HelmRelease that was actually searched for), so it is returned
		// unchanged rather than replaced with a vaguer one.
		return discoveredFile{}, err
	}

	altRef := gitops.ObjectRef{Kind: kind, Name: name}
	altFound, altErr := locateObjectFile(ctx, provider, binding, repoURL, revision, sourceDir, altRef)
	if altErr != nil {
		return discoveredFile{}, fmt.Errorf("%w (also tried %s %q, the object this incident's own sync-failure message names, under the same directory: %s)",
			err, kind, name, altErr)
	}
	altFound.IdentitySource = "sync_failure_message"
	return altFound, nil
}

// findAdmissionRejectionIdentity reads the Message text of the SAME finding
// (gvk/namespace/name) loadIncidentObject already resolved this incident's
// object onto, and asks identityFromMessages whether any of them name a
// different object using the shape an admission-time rejection carries.
//
// Newest first: Argo re-emits the same operationState.message on every retry
// while a sync keeps failing (syncfailure.go's argoSyncIsFailing), so several
// findings can carry an identical message and the newest is as good as any.
// Capped at 5 rather than "the newest one only" so a message that failed to
// parse (a different, unrelated Warning that happened to land on the same
// object) does not hide one that does, a few rows further back.
func findAdmissionRejectionIdentity(ctx context.Context, tx pgx.Tx, incidentID, gvk, namespace, name string) (kind, objName string, ok bool) {
	rows, err := tx.Query(ctx,
		`SELECT message FROM findings
		  WHERE incident_id = $1 AND gvk = $2 AND namespace IS NOT DISTINCT FROM $3 AND object_name = $4
		    AND message IS NOT NULL
		  ORDER BY occurred_at DESC LIMIT 5`,
		incidentID, gvk, nullIfEmpty(namespace), name)
	if err != nil {
		logger.ErrorContext(ctx, "querying the incident's findings for the admission-rejection identity failed", logging.IncidentID(incidentID), logging.Err(err))
		return "", "", false
	}
	defer rows.Close()

	var messages []string
	for rows.Next() {
		var message *string
		if scanErr := rows.Scan(&message); scanErr != nil || message == nil {
			continue
		}
		messages = append(messages, *message)
	}
	if err := rows.Err(); err != nil {
		logger.ErrorContext(ctx, "reading the incident's findings for the admission-rejection identity failed", logging.IncidentID(incidentID), logging.Err(err))
	}
	return identityFromMessages(messages)
}

// identityFromMessages is findAdmissionRejectionIdentity's pure half, split
// out the same way dryRunAvailableFromFacts and pickOwnershipQueryTuple are
// (routing.go, repository_change.go) so the actual decision — which message,
// if any, names a parseable identity — has a real unit test rather than only
// one gated behind a database connection.
func identityFromMessages(messages []string) (kind, name string, ok bool) {
	for _, message := range messages {
		if k, n, ok := gitops.ParseAdmissionRejectionObject(message); ok {
			return k, n, true
		}
	}
	return "", "", false
}

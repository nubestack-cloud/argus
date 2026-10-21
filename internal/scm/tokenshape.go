package scm

// This file implements the refusal docs/USER_GUIDE.md §3 has always promised:
//
//	"ARGUS refuses a classic broad-scope token: an exposure that cannot be sized
//	 cannot be accepted, only ignored."
//
// A documentation audit (WORKLOG §187) found that sentence was **not true** —
// registration checked only that the token was non-empty, so a classic PAT
// carrying `repo` scope was accepted silently and worked through every code path.
//
// That failure pointed the wrong way. An operator reading the guide can
// reasonably infer that if their token were over-scoped, ARGUS would have said
// so. It never would, and the credential they pasted grants write access to every
// repository their account can reach — inside a product whose whole
// repository-write story is least privilege. The doc could have been downgraded
// to advice instead; making the guarantee real is the better answer, because the
// claim is a safety claim and the check is four string comparisons.
//
// # Why by prefix, and why not by scope probe
//
// GitHub's token prefixes are documented, stable, and visible without a network
// call (`github_pat_` for fine-grained, `ghp_` for a classic PAT, and so on). The
// alternative is to probe the API once and refuse any response carrying an
// `X-OAuth-Scopes` header, which only classic tokens return — strictly more
// accurate, and rejected here anyway: it turns a validation into a network
// round trip that can fail for unrelated reasons, and it means the refusal
// message depends on whether GitHub was reachable. A local check gives the same
// answer instantly and identically every time.
//
// # What is deliberately still accepted
//
// A GitHub **App installation** token (`ghs_`) is allowed. It is not a classic
// PAT: it is scoped to an installation and to the permissions that installation
// was granted, which is as narrow as a fine-grained PAT and often narrower. The
// doc's objection is to credentials whose reach cannot be sized, and an
// installation token's reach can be.
//
// An unrecognised shape is also accepted rather than refused. GitHub Enterprise
// Server has shipped several token formats over its life, and a self-hosted
// operator on an older release should not be locked out by a prefix table
// written against github.com. The refusal names the shapes it is certain about;
// everything else falls through, and the guide still advises fine-grained.

import (
	"fmt"
	"strings"
)

// classicTokenPrefixes are the GitHub token shapes whose reach is
// account-wide and cannot be scoped to a repository.
//
// Each is listed with what it is, because "refused: bad prefix" is not an
// actionable message and an operator needs to know which of their several
// credentials they have pasted.
var classicTokenPrefixes = map[string]string{
	"ghp_": "a classic personal access token",
	"gho_": "an OAuth app token",
	"ghu_": "a GitHub App user-to-server token",
	"ghr_": "a GitHub App refresh token",
}

// ClassicTokenRefusal returns a human-readable reason when token is a
// broad-scope GitHub credential, or "" when it is acceptable.
//
// Returns a reason rather than an error so the caller decides the status code and
// the problem type, matching how the rest of this package reports validation.
func ClassicTokenRefusal(token string) string {
	t := strings.TrimSpace(token)
	if t == "" {
		return ""
	}
	for prefix, what := range classicTokenPrefixes {
		if strings.HasPrefix(t, prefix) {
			return fmt.Sprintf("that looks like %s (it begins %q). Its reach is the whole account, "+
				"so it cannot be scoped to this repository and its exposure cannot be sized. Create a "+
				"fine-grained token instead, scoped to only this repository, granting Contents "+
				"(read and write) and Pull requests (read and write) — nothing else", what, prefix)
		}
	}
	// The pre-prefix classic format: 40 lowercase hex characters. Still valid on
	// github.com and common on older Enterprise Server installs.
	if len(t) == 40 && isLowerHex(t) {
		return "that is a 40-character hexadecimal token, which is GitHub's pre-2021 classic " +
			"personal access token format. Its reach is the whole account and cannot be scoped to " +
			"this repository. Create a fine-grained token instead, granting Contents (read and " +
			"write) and Pull requests (read and write) on this repository only"
	}
	return ""
}

func isLowerHex(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

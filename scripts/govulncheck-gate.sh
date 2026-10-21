#!/usr/bin/env bash
# Go dependency vulnerability gate — PROJECT.md G10 ("no dependency ... scanning").
#
# Runs `govulncheck` (govulncheck.go.dev's own tool, the standard way to check
# a Go module against the Go vulnerability database) and fails only on a
# CALL-REACHABLE finding that is not already in scripts/govulncheck-baseline.json
# — the same "fail on drift, not on existing debt" shape web/scripts/design-lint.mjs
# already uses for this repo's design-lint baseline, applied to the same
# problem here: a scanner that always failed on day one either gets a mass
# ignore-file bolted on to force it green (the thing PROJECT.md G10 explicitly
# forbids: "do not pin backwards or add an ignore file to get green"), or it
# gets disabled entirely the first time someone is in a hurry. Recording
# what's ALREADY true and gating only on what's NEW keeps the check both
# honest and enforceable.
#
# "Call-reachable" (govulncheck's own distinction, not this script's
# invention): a vulnerable symbol this module's own code actually calls,
# transitively — not merely a vulnerable module sitting in go.sum that
# nothing here ever invokes. That second category is real dependency risk
# too, but govulncheck's own text-mode output separates it out because it is
# actionable differently (module-level version bump vs "this code path is
# provably exposed"); this gate only fails on the second, stronger claim.
#
# Usage:
#   ./scripts/govulncheck-gate.sh                 # gate: fail on new findings
#   ./scripts/govulncheck-gate.sh --update-baseline   # after actually fixing something
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v govulncheck >/dev/null 2>&1; then
  echo "govulncheck not found. Install with:" >&2
  echo "  go install golang.org/x/vuln/cmd/govulncheck@latest" >&2
  exit 2
fi

BASELINE="scripts/govulncheck-baseline.json"
RAW_JSON="$(mktemp)"
trap 'rm -f "$RAW_JSON"' EXIT

# Exit code from govulncheck itself is deliberately ignored here (`|| true`):
# it exits non-zero the moment ANY vulnerability is found, baseline or not,
# which is exactly the signal this script replaces with its own baseline-aware
# comparison below.
govulncheck -json ./... > "$RAW_JSON" 2>&1 || true

python3 - "$RAW_JSON" "$BASELINE" "${1:-}" <<'PYEOF'
import json
import sys

raw_path, baseline_path, mode = sys.argv[1], sys.argv[2], sys.argv[3]

with open(raw_path) as f:
    text = f.read()

dec = json.JSONDecoder()
idx, n = 0, len(text)
findings = []
while idx < n:
    while idx < n and text[idx] in " \t\r\n":
        idx += 1
    if idx >= n:
        break
    try:
        obj, end = dec.raw_decode(text, idx)
    except json.JSONDecodeError:
        print("error: could not parse govulncheck's JSON output — see raw output above", file=sys.stderr)
        sys.exit(2)
    idx = end
    if "finding" in obj:
        findings.append(obj["finding"])

affected = sorted({
    fnd["osv"]
    for fnd in findings
    if any(t.get("function") for t in fnd.get("trace", []))
})

with open(baseline_path) as f:
    baseline = json.load(f)
known = set(baseline.get("ids", []))

if mode == "--update-baseline":
    baseline["ids"] = affected
    with open(baseline_path, "w") as f:
        json.dump(baseline, f, indent=2)
        f.write("\n")
    print(f"baseline updated: {len(affected)} call-reachable finding(s) recorded in {baseline_path}")
    sys.exit(0)

new = [i for i in affected if i not in known]
resolved = [i for i in known if i not in affected]

print(f"call-reachable findings: {len(affected)} ({len(known & set(affected))} known, {len(new)} new)")
for vid in affected:
    tag = "NEW" if vid in new else "known (baseline)"
    print(f"  {vid} [{tag}]  https://pkg.go.dev/vuln/{vid}")

if resolved:
    print()
    print(f"{len(resolved)} previously-baselined finding(s) no longer reproduce — run with --update-baseline to record the fix:")
    for vid in resolved:
        print(f"  {vid}")

if new:
    print()
    print(f"FAIL: {len(new)} new call-reachable vulnerability finding(s). Fix them, or if a fix genuinely isn't available yet, get the owner's explicit sign-off before adding to {baseline_path} — see that file's own comment.", file=sys.stderr)
    sys.exit(1)

print()
print("OK: no new call-reachable findings beyond the recorded baseline.")
PYEOF

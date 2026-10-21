#!/usr/bin/env bash
# Re-resolve the published images' digests for a given tag and rewrite the
# three places this repo pins them: deploy/helm/argus-hub/values.yaml's
# `image.digest` and `cliRunner.image.digest`, and
# deploy/helm/argus-agent/values.yaml's `image.digest`.
#
# WHY THIS SCRIPT EXISTS. PROJECT.md G10's acceptance criterion is a signed,
# versioned, scanned artifact — a chart shipping `image.tag: latest` fails
# that on its own, because a tag can be silently repointed at different bytes
# (by a compromised publishing credential, or by accident) with no change
# anyone reviews. A digest can't move like that. But a digest that is pinned
# once and never updated is worse than useless: it looks like a supply-chain
# control while quietly preventing every future upgrade from ever reaching an
# installed chart. Pinning a digest is only honest if there is also a named,
# working way to move the pin forward — this script is that way, and it is
# safe to run again and again: it replaces whatever tag/digest is currently
# in the file by locating the field structurally (top-level `image:` block vs
# nested `cliRunner: image:` block, by indentation), not by matching today's
# literal value — so a second run after a second release works exactly like
# the first.
#
# WHEN TO RUN THIS. After every image publish (today: ./scripts/build-images.sh
# plus whatever pushes those tags — this repo does not push for you, and
# neither does this script). Then commit the resulting values.yaml diff
# alongside the version bump, as one reviewable change: "here is the new
# image, and here is the exact chart change that starts shipping it."
#
# WHAT IT DOES NOT DO: push anything, sign anything, or touch a registry
# beyond a read-only manifest inspect. It only ever re-points these charts at
# digests that some other, already-completed publish step produced.
#
# Usage:
#   ./scripts/pin-image-digests.sh <tag>              # same tag for all three images
#   ./scripts/pin-image-digests.sh --hub-tag v0.2.0 --agent-tag v0.2.0 --cli-runner-tag v0.2.0
#
# Requires: docker buildx (for `imagetools inspect`, which reads the registry's
# manifest — no image pull needed), network access to Docker Hub, and python3
# (used only for an indentation-aware in-place edit that leaves every comment
# in values.yaml untouched — a plain YAML dump/reload would discard them).
set -euo pipefail
cd "$(dirname "$0")/.."

HUB_REPO="nubestack/argus-hub"
AGENT_REPO="nubestack/argus-agent"
CLI_RUNNER_REPO="nubestack/argus-cli-runner"

HUB_TAG=""
AGENT_TAG=""
CLI_RUNNER_TAG=""
# Where deploy/helm lives: the repository by default; scripts/release/
# package-charts.sh points it at a staged copy so a release never edits the
# working tree it was cut from.
CHART_ROOT="."

if [[ $# -eq 1 && "$1" != --* ]]; then
  HUB_TAG="$1"
  AGENT_TAG="$1"
  CLI_RUNNER_TAG="$1"
else
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --hub-tag) HUB_TAG="$2"; shift 2 ;;
      --agent-tag) AGENT_TAG="$2"; shift 2 ;;
      --cli-runner-tag) CLI_RUNNER_TAG="$2"; shift 2 ;;
      --root) CHART_ROOT="$2"; shift 2 ;;
      *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
  done
fi

if [[ -z "$HUB_TAG" || -z "$AGENT_TAG" || -z "$CLI_RUNNER_TAG" ]]; then
  echo "usage: $0 <tag>" >&2
  echo "   or: $0 --hub-tag <tag> --agent-tag <tag> --cli-runner-tag <tag> [--root <dir holding deploy/helm>]" >&2
  exit 2
fi

resolve_digest() {
  local repo="$1" tag="$2"
  # `imagetools inspect` talks to the registry's manifest API directly — it
  # never pulls image layers, so this is cheap and side-effect-free even
  # against a large image.
  local digest
  # Plain-text output's "Digest:" line rather than --format: it is stable
  # across the buildx versions this has been tested against, and unlike
  # --format '{{json .Manifest}}' it works whether the registry returned a
  # single-arch manifest or a multi-arch manifest list (this repo's public
  # images are single-arch today — see the multi-arch note in the Dockerfile
  # and docs/RELEASE_POLICY.md).
  digest="$(docker buildx imagetools inspect "${repo}:${tag}" 2>/dev/null | sed -n 's/^Digest: *//p' | head -1)"
  if [[ -z "$digest" ]]; then
    echo "could not resolve a digest for ${repo}:${tag} — is it published, and reachable from here?" >&2
    exit 1
  fi
  echo "$digest"
}

echo "==> resolving ${HUB_REPO}:${HUB_TAG}"
HUB_DIGEST="$(resolve_digest "$HUB_REPO" "$HUB_TAG")"
echo "    $HUB_DIGEST"

echo "==> resolving ${AGENT_REPO}:${AGENT_TAG}"
AGENT_DIGEST="$(resolve_digest "$AGENT_REPO" "$AGENT_TAG")"
echo "    $AGENT_DIGEST"

echo "==> resolving ${CLI_RUNNER_REPO}:${CLI_RUNNER_TAG}"
CLI_RUNNER_DIGEST="$(resolve_digest "$CLI_RUNNER_REPO" "$CLI_RUNNER_TAG")"
echo "    $CLI_RUNNER_DIGEST"

export HUB_TAG HUB_DIGEST AGENT_TAG AGENT_DIGEST CLI_RUNNER_TAG CLI_RUNNER_DIGEST CHART_ROOT

# Indentation-aware, block-scoped substitution: finds the FIRST `tag:`/
# `digest:` line at a given indent AFTER a given top-level (or nested) key
# header, and replaces only its quoted value. Anchoring on indent + the
# preceding key header (rather than on the old value) is what makes this
# script idempotent across repeated releases — it never needs to know what
# was there before. Values arrive via environment variables, never
# interpolated into the Python source, so a tag containing a regex/quote
# character can't do anything unexpected.
python3 <<'PYEOF'
import os
import re
import sys

def set_field(path, after_header, indent, field, new_value):
    with open(path, "r") as f:
        text = f.read()
    pattern = re.compile(
        r"(^" + re.escape(after_header) + r".*?\n(?:.*\n)*?" + re.escape(indent) + field + r": )\"[^\"]*\"",
        re.MULTILINE,
    )
    escaped = new_value.replace("\\", "\\\\")
    new_text, n = pattern.subn(lambda m: m.group(1) + '"' + escaped + '"', text, count=1)
    if n != 1:
        print(f"error: could not find {field}: under {after_header!r} at indent {indent!r} in {path}", file=sys.stderr)
        sys.exit(1)
    with open(path, "w") as f:
        f.write(new_text)

hub_values = os.path.join(os.environ["CHART_ROOT"], "deploy/helm/argus-hub/values.yaml")
agent_values = os.path.join(os.environ["CHART_ROOT"], "deploy/helm/argus-agent/values.yaml")

hub_tag = os.environ["HUB_TAG"]
hub_digest = os.environ["HUB_DIGEST"]
cli_tag = os.environ["CLI_RUNNER_TAG"]
cli_digest = os.environ["CLI_RUNNER_DIGEST"]
agent_tag = os.environ["AGENT_TAG"]
agent_digest = os.environ["AGENT_DIGEST"]

# Top-level `image:` block in the hub chart (2-space indent).
set_field(hub_values, "image:", "  ", "tag", hub_tag)
set_field(hub_values, "image:", "  ", "digest", hub_digest)

# Nested `cliRunner: / image:` block in the hub chart (4-space indent) —
# anchored on "cliRunner:" so it never matches the top-level image block.
set_field(hub_values, "cliRunner:", "    ", "tag", cli_tag)
set_field(hub_values, "cliRunner:", "    ", "digest", cli_digest)

# Top-level `image:` block in the agent chart (2-space indent).
set_field(agent_values, "image:", "  ", "tag", agent_tag)
set_field(agent_values, "image:", "  ", "digest", agent_digest)

# The agent image the hub offers through "Upgrade agent": always the agent
# released with this hub, or the hub would move agents onto an older build.
with open(hub_values) as f:
    text = f.read()
text, n = re.subn(r'^agentImage: "[^"]*"', 'agentImage: "nubestack/argus-agent@' + agent_digest + '"', text, count=1, flags=re.MULTILINE)
if n != 1:
    print(f"error: could not find agentImage: in {hub_values}", file=sys.stderr)
    sys.exit(1)
with open(hub_values, "w") as f:
    f.write(text)

print("rewrote:")
print(f"  {hub_values} (image.tag/digest, cliRunner.image.tag/digest, agentImage)")
print(f"  {agent_values} (image.tag/digest)")
PYEOF

echo
echo "Verify before committing:"
echo "  helm template t deploy/helm/argus-hub --set ingress.host=x.example.com | grep 'image:'"
echo "  helm template t deploy/helm/argus-agent --set hub.apiUrl=https://x --set enrollment.token=x | grep 'image:'"
echo "  go test ./deploy/helm/..."

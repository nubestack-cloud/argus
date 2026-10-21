#!/usr/bin/env bash
# Package the ARGUS Helm charts for a release, reproducibly.
#
# A published chart must install exactly the images of its release, today and
# in a year. So this stamps, into a staged copy of deploy/helm (never the
# working tree, unless --in-place):
#   - each Chart.yaml's version and appVersion: the release version;
#   - each chart's name: argus-hub-chart / argus-agent-chart. Docker Hub keeps
#     a chart and an image of the same name in ONE repository, where a chart
#     tag 0.2.0 would overwrite the image tag 0.2.0. Resource names do not
#     change with it (the charts' helpers fix the logical name);
#   - every image as tag AND digest (scripts/pin-image-digests.sh), so the
#     chart pulls the bytes that were scanned and signed, not whatever a tag
#     points at later;
#   - the hub's agentChart.version, so the hub's "Enroll a cluster" command
#     installs the agent chart of the same release.
# Then it lints and test-renders both charts, packages them, and with --push
# publishes them as OCI artifacts.
#
#   scripts/release/package-charts.sh --version 0.2.0 --tag 0.2.0
#   scripts/release/package-charts.sh --version 0.2.0-rc.1 \
#       --hub-tag <tag> --agent-tag <tag> --cli-runner-tag <tag> \
#       --push oci://registry-1.docker.io/nubestack
#
# --in-place stamps deploy/helm itself.
set -euo pipefail
cd "$(dirname "$0")/../.."

VERSION="" HUB_TAG="" AGENT_TAG="" CLI_RUNNER_TAG="" OUT="dist/charts" PUSH="" IN_PLACE=false DIGESTS=true
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --tag) HUB_TAG="$2"; AGENT_TAG="$2"; CLI_RUNNER_TAG="$2"; shift 2 ;;
    --hub-tag) HUB_TAG="$2"; shift 2 ;;
    --agent-tag) AGENT_TAG="$2"; shift 2 ;;
    --cli-runner-tag) CLI_RUNNER_TAG="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --push) PUSH="$2"; shift 2 ;;
    --in-place) IN_PLACE=true; shift ;;
    # For a dry run whose images were never pushed, so have no digest: the
    # charts carry the tags only. Never use it for anything published.
    --no-digests) DIGESTS=false; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "--version must be a semantic version such as 0.2.0 or 0.2.0-rc.1 (got '${VERSION}')" >&2
  exit 2
fi
if [[ -z "$HUB_TAG" || -z "$AGENT_TAG" || -z "$CLI_RUNNER_TAG" ]]; then
  echo "give the images: --tag <tag> for all three, or --hub-tag, --agent-tag and --cli-runner-tag" >&2
  exit 2
fi

if $IN_PLACE; then
  ROOT="."
else
  ROOT="$(mktemp -d)"
  trap 'rm -rf "$ROOT"' EXIT
  mkdir -p "$ROOT/deploy/helm"
  cp -R deploy/helm/argus-hub deploy/helm/argus-agent "$ROOT/deploy/helm/"
fi

if $DIGESTS; then
  scripts/pin-image-digests.sh --hub-tag "$HUB_TAG" --agent-tag "$AGENT_TAG" --cli-runner-tag "$CLI_RUNNER_TAG" --root "$ROOT"
else
  if [[ -n "$PUSH" ]]; then echo "--no-digests cannot be combined with --push: a published chart pins digests" >&2; exit 2; fi
  python3 - "$ROOT" "$HUB_TAG" "$AGENT_TAG" "$CLI_RUNNER_TAG" <<'PY'
import re, sys, os
root, hub, agent, cli = sys.argv[1:]
def pin(path, header, indent, tag):
    text = open(path).read()
    for field, value in (("tag", tag), ("digest", "")):
        text, n = re.subn(r"(^" + re.escape(header) + r".*?\n(?:.*\n)*?" + re.escape(indent) + field + r": )\"[^\"]*\"",
                          lambda m: m.group(1) + '"' + value + '"', text, count=1, flags=re.MULTILINE)
        if n != 1:
            sys.exit(f"error: {field} under {header} not found in {path}")
    open(path, "w").write(text)
hv = os.path.join(root, "deploy/helm/argus-hub/values.yaml")
pin(hv, "image:", "  ", hub)
pin(hv, "cliRunner:", "    ", cli)
pin(os.path.join(root, "deploy/helm/argus-agent/values.yaml"), "image:", "  ", agent)
PY
fi

python3 - "$ROOT" "$VERSION" <<'PY'
import re, sys, os
root, version = sys.argv[1], sys.argv[2]
def sub(path, pattern, repl):
    with open(path) as f:
        text = f.read()
    new, n = re.subn(pattern, repl, text, count=1, flags=re.MULTILINE)
    if n != 1:
        sys.exit(f"error: {pattern!r} not found in {path}")
    with open(path, "w") as f:
        f.write(new)
for chart in ("argus-hub", "argus-agent"):
    meta = os.path.join(root, "deploy/helm", chart, "Chart.yaml")
    sub(meta, r"^name: .*$", f"name: {chart}-chart")
    sub(meta, r"^version: .*$", f"version: {version}")
    sub(meta, r"^appVersion: .*$", f'appVersion: "{version}"')
# The hub chart carries the agent chart as its localAgent dependency, by the
# agent chart's (renamed) name and this release's version.
hub_meta = os.path.join(root, "deploy/helm/argus-hub/Chart.yaml")
sub(hub_meta, r"^(  - name: )argus-agent$", r"\g<1>argus-agent-chart")
sub(hub_meta, r'^(    version: )"[^"]*"', r'\g<1>"' + version + '"')
# The hub's enroll command installs the agent chart of the same release.
sub(os.path.join(root, "deploy/helm/argus-hub/values.yaml"),
    r'^(agentChart:\n  ref: .*\n  version: )"[^"]*"', r'\g<1>"' + version + '"')
PY

# Lint and render both, the hub as the minimal install.
helm lint "$ROOT/deploy/helm/argus-hub" --set ingress.host=lint.invalid
helm lint "$ROOT/deploy/helm/argus-agent" --set hub.apiUrl=https://lint.invalid --set enrollment.token=lint
helm template lint "$ROOT/deploy/helm/argus-hub" --namespace argus-system --set ingress.host=lint.invalid >/dev/null
helm template lint "$ROOT/deploy/helm/argus-agent" --set hub.apiUrl=https://lint.invalid --set enrollment.token=lint >/dev/null

mkdir -p "$OUT"
helm package "$ROOT/deploy/helm/argus-hub" -d "$OUT"
helm package "$ROOT/deploy/helm/argus-agent" -d "$OUT"
echo "==> packaged:"
ls -1 "$OUT"/argus-*-chart-"$VERSION".tgz

if [[ -n "$PUSH" ]]; then
  for chart in argus-hub-chart argus-agent-chart; do
    helm push "$OUT/${chart}-${VERSION}.tgz" "$PUSH"
  done
  echo "==> install with:"
  echo "    helm install argus-hub ${PUSH}/argus-hub-chart --version ${VERSION} ..."
fi

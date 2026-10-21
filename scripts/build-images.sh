#!/usr/bin/env bash
# Build the ARGUS images with the version stamped in automatically.
#
# WHY THIS SCRIPT EXISTS. The sign-in screens print the hub's version, and it
# comes from `internal/buildinfo` — which is fed at link time by the
# Dockerfile's `VERSION` build arg. A `docker build` that omits that arg still
# succeeds and still ships; the binary just reports "dev". Nothing breaks
# loudly, so the failure mode is a login page quietly claiming to be a build
# nobody can identify.
#
# So: never `docker build` these by hand. Run this.
#
#   ./scripts/build-images.sh              # hub only, the usual case
#   ./scripts/build-images.sh hub agent    # named targets
#   ./scripts/build-images.sh all
#
# The version is `git describe --tags --always --dirty`, which gives a tag if
# HEAD has one, otherwise the short commit, with "-dirty" appended when the
# tree has uncommitted changes. A dirty build reporting "-dirty" is the point:
# it is the honest answer, and it is how you can tell a published image from a
# local experiment.
#
# Each target is tagged twice — `:<version>` and `:latest` — because
# deploy/compose and deploy/helm now track `latest`, while the pinned tag stays
# available for rollback.
set -euo pipefail

cd "$(dirname "$0")/.."

VERSION="$(git describe --tags --always --dirty 2>/dev/null || echo dev)"
if [[ "$VERSION" == "dev" ]]; then
  echo "WARNING: not in a git repository (or git unavailable) — stamping 'dev'" >&2
fi

declare -A TARGETS=(
  [hub]="nubestack/argus-hub"
  [agent]="nubestack/argus-agent"
  [cli-runner]="nubestack/argus-cli-runner"
)

requested=("$@")
if [[ ${#requested[@]} -eq 0 ]]; then
  requested=(hub)
elif [[ "${requested[0]}" == "all" ]]; then
  requested=(hub agent cli-runner)
fi

for target in "${requested[@]}"; do
  repo="${TARGETS[$target]:-}"
  if [[ -z "$repo" ]]; then
    echo "unknown target: $target (known: ${!TARGETS[*]}, or 'all')" >&2
    exit 2
  fi
  echo "==> $repo:$VERSION  (+ :latest)"
  # --target selects the Dockerfile stage; the hub stage is the default one.
  docker build \
    --build-arg "VERSION=$VERSION" \
    --target "$target" \
    -t "$repo:$VERSION" \
    -t "$repo:latest" \
    -f Dockerfile .
done

echo
echo "Built at version: $VERSION"
echo "The hub also keeps the local dev tag used by deploy/compose overrides:"
echo "  docker tag nubestack/argus-hub:$VERSION argus/hub:dev"

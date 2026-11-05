#!/usr/bin/env python3
"""The release version, everywhere it is written.

One release version names the hub, the agent, the CLI runner and both charts
(docs/RELEASE_POLICY.md), and it is written in about twenty places: the charts,
the version the agent reports to the hub, the API spec, and every install
command a reader copies. SITES below is the one list of those places, shared by
both commands, so the list a bump edits and the list CI checks cannot drift.

    scripts/release/version.py check              # every site agrees (CI, every PR)
    scripts/release/version.py check --tag v0.3.0 # ... and equals the tag, and
                                                  # CHANGELOG.md has its notes
    scripts/release/version.py bump 0.3.0         # rewrite every site, and start
                                                  # the CHANGELOG section

Not a site, on purpose: the image `tag:` pins in the two values.yaml files.
They name the last PUBLISHED images (with their digests), so during a release
they still hold the previous version; scripts/pin-image-digests.sh moves them
after the release is out (docs/RELEASING.md, "After the release").

Adding a new place that states the version? Add it to SITES, or `check` will
not know it exists and the next bump will leave it behind.
"""
from __future__ import annotations

import argparse
import glob
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

SEMVER = r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?"
V = "(" + SEMVER + ")"

# (description, path glob relative to the repository root, regex with ONE group
# capturing the version). Every site must match at least once: a site that
# matches nothing means the file changed shape and this list needs updating.
SITES = [
    ("hub chart version", "deploy/helm/argus-hub/Chart.yaml", r"^version: " + V + r"$"),
    ("hub chart appVersion", "deploy/helm/argus-hub/Chart.yaml", r'^appVersion: "' + V + r'"$'),
    ("hub chart's agent dependency", "deploy/helm/argus-hub/Chart.yaml", r'^    version: "' + V + r'"$'),
    ("agent chart version", "deploy/helm/argus-agent/Chart.yaml", r"^version: " + V + r"$"),
    ("agent chart appVersion", "deploy/helm/argus-agent/Chart.yaml", r'^appVersion: "' + V + r'"$'),
    # What every agent reports to the hub, and what the hub's compatibility
    # policy recommends (internal/agentversion). Missing it makes a new agent
    # announce itself as the previous release.
    ("agent build version", "internal/tunnel/protocol.go", r'^const AgentBuildVersion = "' + V + r'"$'),
    ("API spec info.version", "docs/openapi.yaml", r'^  version: "' + V + r'"$'),
    ("install commands", "README.md", r"--version " + V + r"\b"),
    ("install commands", "docs/INSTALL.md", r"--version " + V + r"\b"),
    ("install commands", "deploy/helm/argus-hub/README.md", r"--version " + V + r"\b"),
    ("install commands", "deploy/helm/argus-agent/README.md", r"--version " + V + r"\b"),
    ("install commands", "deploy/helm/templates/*/hub-values.yaml", r"--version " + V + r"\b"),
    ("Argo CD examples", "deploy/examples/argocd/*.yaml", r"targetRevision: " + V + r"\b"),
    ("Flux examples", "deploy/examples/flux/*.yaml", r"\btag: " + V + r"\b"),
    ("compose image default", "deploy/compose/docker-compose.yaml", r"\$\{ARGUS_VERSION:-" + V + r"\}"),
    ("smoke-test image default", "scripts/smoke-test.sh", r"\$\{ARGUS_VERSION:-" + V + r"\}"),
    ("cosign verify example", "docs/SUPPORT.md", r"nubestack/argus-hub:" + V + r"\b"),
]

CHANGELOG = "CHANGELOG.md"
PLACEHOLDER = "<!-- release notes: what changed for an operator, and any upgrade steps -->"


def site_files(pattern: str) -> list[str]:
    return sorted(glob.glob(os.path.join(ROOT, pattern)))


def scan() -> tuple[list[tuple[str, str, int, str]], list[str]]:
    """Every (description, file, line number, version) found, and the sites that
    matched nothing."""
    found, missing = [], []
    for desc, pattern, rx in SITES:
        regex = re.compile(rx)
        hits = 0
        for path in site_files(pattern):
            with open(path, encoding="utf-8") as f:
                for n, line in enumerate(f, 1):
                    for m in regex.finditer(line.rstrip("\n")):
                        found.append((desc, os.path.relpath(path, ROOT), n, m.group(1)))
                        hits += 1
        if hits == 0:
            missing.append(f"{desc} ({pattern})")
    return found, missing


def current_version() -> str:
    with open(os.path.join(ROOT, "deploy/helm/argus-hub/Chart.yaml"), encoding="utf-8") as f:
        m = re.search(r"^version: " + V + r"$", f.read(), re.MULTILINE)
    if not m:
        sys.exit("error: no `version:` in deploy/helm/argus-hub/Chart.yaml")
    return m.group(1)


def changelog_section(version: str) -> str | None:
    """The body of `## [version]` in CHANGELOG.md, matched the way the release
    workflow's notes step matches it, or None when there is no such heading."""
    heading = re.compile(r"^## \[?" + re.escape(version) + r"\]?( |$)")
    body, on = [], False
    with open(os.path.join(ROOT, CHANGELOG), encoding="utf-8") as f:
        for line in f:
            if on and line.startswith("## "):
                break
            if on:
                body.append(line)
            elif heading.match(line):
                on = True
    return "".join(body) if on else None


def check(tag: str | None) -> int:
    found, missing = scan()
    want = current_version()
    errors = [f"no version found for {m}: the file changed shape, so update SITES in scripts/release/version.py" for m in missing]
    for desc, path, n, got in found:
        if got != want:
            errors.append(f"{path}:{n}: {desc} says {got}, the hub chart says {want}")
    if tag is not None:
        tagged = tag[1:] if tag.startswith("v") else tag
        if tagged != want:
            errors.append(f"tag {tag} does not match the version in the tree ({want}): bump with scripts/release/version.py bump {tagged}, or tag v{want}")
        notes = changelog_section(tagged)
        if notes is None:
            errors.append(f"{CHANGELOG} has no '## [{tagged}]' section: the GitHub Release would get generated notes instead")
        elif PLACEHOLDER in notes or not notes.strip():
            errors.append(f"{CHANGELOG}'s '## [{tagged}]' section is still the placeholder: write the release notes")
    if errors:
        print("Release version check failed:", file=sys.stderr)
        for e in errors:
            print("  " + e, file=sys.stderr)
        return 1
    print(f"Release version {want}: {len(found)} references in {len({p for _, p, _, _ in found})} files agree" + (f", and match tag {tag}" if tag else "") + ".")
    return 0


def bump(new: str) -> int:
    if not re.fullmatch(SEMVER, new):
        sys.exit(f"error: {new!r} is not a version such as 0.3.0 or 0.3.0-rc.1")
    old = current_version()
    if new == old:
        sys.exit(f"error: the tree is already at {new}")
    if check(None) != 0:
        sys.exit("error: fix the disagreement above before bumping, so the bump starts from one version")
    changed = set()
    for desc, pattern, rx in SITES:
        regex = re.compile(rx)
        for path in site_files(pattern):
            with open(path, encoding="utf-8") as f:
                text = f.read()
            lines = text.split("\n")
            for i, line in enumerate(lines):
                lines[i] = regex.sub(lambda m: m.group(0).replace(m.group(1), new), line)
            updated = "\n".join(lines)
            if updated != text:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(updated)
                changed.add(os.path.relpath(path, ROOT))
    if changelog_section(new) is None:
        path = os.path.join(ROOT, CHANGELOG)
        with open(path, encoding="utf-8") as f:
            text = f.read()
        first = re.search(r"^## \[", text, re.MULTILINE)
        section = f"## [{new}]\n\n{PLACEHOLDER}\n\n### Fixed\n\n"
        text = text[: first.start()] + section + text[first.start():] if first else text.rstrip("\n") + "\n\n" + section
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        changed.add(CHANGELOG)
    print(f"Bumped {old} -> {new} in {len(changed)} files:")
    for p in sorted(changed):
        print("  " + p)
    print(f"\nNext: write the '## [{new}]' notes in {CHANGELOG} (replace the placeholder), then")
    print("  scripts/release/version.py check")
    return check(None)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="every version reference agrees (and matches --tag)")
    c.add_argument("--tag", help="the release tag being published, e.g. v0.3.0")
    b = sub.add_parser("bump", help="rewrite every version reference")
    b.add_argument("version")
    a = p.parse_args()
    return check(a.tag) if a.cmd == "check" else bump(a.version)


if __name__ == "__main__":
    sys.exit(main())

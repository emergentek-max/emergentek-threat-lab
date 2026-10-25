#!/usr/bin/env python3
"""Prune accumulated threat-intel releases on GitHub.

Phase 1: delete every versioned release (tag v1.0-*) and its git tag.
Phase 2: strip the rolling "latest" release down to its newest .bin,
         newest .sha256, and latest.json.

Requires the GitHub CLI (gh) authenticated for the repo.

Usage:
    python cleanup_releases.py            # dry-run, prints what would happen
    python cleanup_releases.py --apply    # actually delete
"""

import json
import subprocess
import sys

REPO = "emergentek-max/emergentek-threat-lab"
KEEP_ASSET_NAMES = {"latest.json"}
KEEP_ARTIFACTS_PER_EXT = 1  # keep newest N .bin and .sha256 on "latest"


def gh(*args, check=True):
    """Run a gh CLI command, return parsed JSON stdout."""
    result = subprocess.run(
        ["gh", *args], capture_output=True, text=True, check=check
    )
    return result.stdout


def main():
    apply = "--apply" in sys.argv
    if not apply:
        print("DRY-RUN mode — pass --apply to delete for real.\n")

    # ---- Phase 1: delete versioned releases ---------------------------------
    releases = json.loads(
        gh(
            "release", "list", "-R", REPO,
            "--limit", "1000", "--json", "tagName,name",
        )
    )
    versioned = [r["tagName"] for r in releases if r["tagName"].startswith("v1.0-")]
    print(f"Phase 1: {len(versioned)} versioned releases to delete")
    for tag in versioned:
        print(f"  {'deleting' if apply else 'would delete'} release + tag: {tag}")
        if apply:
            gh("release", "delete", tag, "-R", REPO, "--yes", "--cleanup-tag")

    # ---- Phase 2: prune assets on the "latest" release ----------------------
    latest = json.loads(
        gh("api", f"repos/{REPO}/releases/tags/latest", "--jq", ".assets")
    )
    assets = latest if isinstance(latest, list) else []

    keep_ids = set()
    by_ext = {}
    for asset in sorted(assets, key=lambda a: a["created_at"], reverse=True):
        name = asset["name"]
        if name in KEEP_ASSET_NAMES:
            keep_ids.add(asset["id"])
            continue
        ext = name.rsplit(".", 1)[-1]
        bucket = by_ext.setdefault(ext, [])
        if len(bucket) < KEEP_ARTIFACTS_PER_EXT:
            bucket.append(asset["id"])
            keep_ids.add(asset["id"])

    doomed = [a for a in assets if a["id"] not in keep_ids]
    print(
        f"\nPhase 2: 'latest' has {len(assets)} assets — "
        f"keeping {len(keep_ids)}, deleting {len(doomed)}"
    )
    for asset in doomed:
        print(
            f"  {'deleting' if apply else 'would delete'} "
            f"{asset['name']} ({asset['created_at']})"
        )
        if apply:
            gh("api", "-X", "DELETE", f"repos/{REPO}/releases/assets/{asset['id']}")

    if not apply:
        print("\nDry-run complete. Re-run with --apply to execute.")


if __name__ == "__main__":
    main()

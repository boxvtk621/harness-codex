#!/usr/bin/env python3
"""Generate or verify the fixed-source extraction provenance manifest."""

import argparse
import csv
import hashlib
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "provenance" / "source-manifest.csv"
SOURCE_COMMIT = "9736f8c74e2f242cbe63dda3b0c74b42bc8d04d9"
FIELDS = ("status", "source_commit", "source_path", "destination_path", "source_sha256", "destination_sha256", "rationale")
EXCLUSIONS = (
    ("harness/adapters/cursor", "Cursor provider is outside the Codex-only repository"),
    ("harness/node/history_coordinator_integration_test.go", "consumer coordinator test belongs to the source monorepo"),
    ("internal/harnessclient", "Panel/Router consumer client is outside the producer boundary"),
    ("internal/harnesstunnel", "host tunnel is outside the container/API producer boundary"),
    ("internal/agentservice", "Agent Service is an independent application"),
    ("internal/harnessrouter", "Router is an independent application"),
    ("internal/panel", "Panel is an independent application"),
    ("web", "Panel UI assets are outside the producer repository"),
    ("scripts/provision_codex_node.py", "production provisioning and registry coupling are intentionally excluded"),
    ("scripts/harness-probe", "historical feasibility probes are not runtime dependencies"),
    ("deploy", "deployment/release topology is not transferred; Dockerfile.codex is adapted separately"),
)

# Repository-native provider authentication was designed and implemented here;
# these files were not extracted from the pinned monorepo source.
LOCAL_DESTINATIONS = {
    "adapters/codex/provider_auth.go",
    "adapters/codex/provider_auth_test.go",
    "api/check-provider-auth-v1.mjs",
    "api/provider-auth-v1.schema.json",
    "api/provider_auth_test.go",
    "internal/providerauth/types.go",
    "runtime/provider_auth.go",
    "runtime/provider_auth_internal_test.go",
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def git_bytes(source, path):
    command = ["git", "-c", f"safe.directory={source.as_posix()}", "-C", str(source), "show", f"{SOURCE_COMMIT}:{path}"]
    return subprocess.run(command, check=True, capture_output=True).stdout


def destination_bytes(path):
    """Return canonical repository bytes while still detecting real worktree edits."""
    relative = path.relative_to(ROOT).as_posix()
    tracked = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "--error-unmatch", "--", relative],
        capture_output=True,
    )
    if tracked.returncode != 0:
        return path.read_bytes()

    worktree_clean = subprocess.run(
        ["git", "-C", str(ROOT), "diff", "--quiet", "--", relative],
        capture_output=True,
    )
    if worktree_clean.returncode != 0:
        return path.read_bytes()

    index_changed = subprocess.run(
        ["git", "-C", str(ROOT), "diff", "--cached", "--quiet", "--", relative],
        capture_output=True,
    )
    revision = f":{relative}" if index_changed.returncode == 1 else f"HEAD:{relative}"
    result = subprocess.run(
        ["git", "-C", str(ROOT), "show", revision],
        check=False,
        capture_output=True,
    )
    return result.stdout if result.returncode == 0 else path.read_bytes()


def destination_map():
    result = {}
    roots = {
        "adapters/codex": "harness/adapters/codex",
        "runtime": "harness/node",
        "fixture": "harness/fixture",
        "integration": "harness/integration",
        "cmd/harness-node": "harness/cmd/harness-node",
        "cmd/harness-tool-runner": "harness/cmd/harness-tool-runner",
        "internal/harnessadapter": "internal/harnessadapter",
        "internal/harnessprotocol": "internal/harnessprotocol",
        "internal/harnessbarrier": "internal/harnessbarrier",
        "internal/historyreplica": "internal/historyreplica",
        "internal/logicaldelete": "internal/logicaldelete",
        "internal/transcriptview": "internal/transcriptview",
        "internal/strictjson": "internal/strictjson",
        "internal/toolrunner": "internal/toolrunner",
    }
    for destination_root, source_root in roots.items():
        for path in sorted((ROOT / destination_root).rglob("*")):
            if path.is_file():
                relative = path.relative_to(ROOT).as_posix()
                if relative in LOCAL_DESTINATIONS:
                    continue
                suffix = path.relative_to(ROOT / destination_root).as_posix()
                result[relative] = f"{source_root}/{suffix}"
    for path in sorted((ROOT / "api").glob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT).as_posix()
        if relative in LOCAL_DESTINATIONS:
            continue
        result[relative] = ("harness/server/" + path.name) if path.name in {"server.go", "server_test.go"} else ("api/" + path.name)
    # The consumer package is deliberately not imported. Its narrowly scoped
    # Private HTTP behavior is adapted into a test-local client instead.
    result["integration/client_test.go"] = "internal/harnessclient/client.go"
    result.update({
        "Dockerfile": "deploy/components/Dockerfile.codex",
        "go.mod": "go.mod",
        "go.sum": "go.sum",
        "scripts/setup.py": "scripts/harness-alpha/setup.py",
        "scripts/smoke.py": "scripts/test_component_container.py",
        "docs/harness-v1.md": "docs/harness-v1.md",
    })
    return result


def write_manifest(source):
    rows = []
    for destination, source_path in sorted(destination_map().items()):
        transferred_bytes = destination_bytes(ROOT / destination)
        source_bytes = git_bytes(source, source_path)
        rows.append({
            "status": "included" if source_bytes == transferred_bytes else "adapted",
            "source_commit": SOURCE_COMMIT,
            "source_path": source_path,
            "destination_path": destination,
            "source_sha256": digest(source_bytes),
            "destination_sha256": digest(transferred_bytes),
            "rationale": "byte-identical transfer" if source_bytes == transferred_bytes else "standalone path/module/provider adaptation",
        })
    for path, reason in EXCLUSIONS:
        rows.append({"status": "excluded", "source_commit": SOURCE_COMMIT, "source_path": path,
                     "destination_path": "", "source_sha256": "", "destination_sha256": "", "rationale": reason})
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    with MANIFEST.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def verify(source):
    if not MANIFEST.is_file():
        raise SystemExit("provenance manifest is missing")
    with MANIFEST.open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))
    if not rows or tuple(rows[0]) != FIELDS:
        raise SystemExit("provenance manifest columns are invalid")
    mapped = {}
    excluded = {}
    failures = []
    for row in rows:
        if row["source_commit"] != SOURCE_COMMIT:
            failures.append(f"wrong source commit: {row['source_path']}")
        if row["status"] == "excluded":
            if row["destination_path"] or row["source_sha256"] or row["destination_sha256"]:
                failures.append(f"excluded row carries destination/hash data: {row['source_path']}")
            if row["source_path"] in excluded:
                failures.append(f"duplicate exclusion: {row['source_path']}")
            excluded[row["source_path"]] = row["rationale"]
            continue
        if row["status"] not in {"included", "adapted"}:
            failures.append(f"invalid status: {row['source_path']}")
            continue
        destination = row["destination_path"]
        if destination in mapped:
            failures.append(f"duplicate destination: {destination}")
            continue
        mapped[destination] = row["source_path"]
        path = ROOT / destination
        if not path.is_file() or digest(destination_bytes(path)) != row["destination_sha256"]:
            failures.append(f"destination digest mismatch: {destination}")
        if source is not None:
            try:
                source_hash = digest(git_bytes(source, row["source_path"]))
            except subprocess.CalledProcessError:
                failures.append(f"source object missing: {row['source_path']}")
            else:
                if source_hash != row["source_sha256"]:
                    failures.append(f"source digest mismatch: {row['source_path']}")
    expected = destination_map()
    missing = sorted(set(expected) - set(mapped))
    extra = sorted(set(mapped) - set(expected))
    failures.extend(f"unmatched destination: {path}" for path in missing)
    failures.extend(f"ambiguous/stale destination: {path}" for path in extra)
    expected_exclusions = dict(EXCLUSIONS)
    failures.extend(f"missing exclusion: {path}" for path in sorted(set(expected_exclusions) - set(excluded)))
    failures.extend(f"unexpected exclusion: {path}" for path in sorted(set(excluded) - set(expected_exclusions)))
    for path in sorted(set(excluded) & set(expected_exclusions)):
        if excluded[path] != expected_exclusions[path]:
            failures.append(f"exclusion rationale mismatch: {path}")
    if failures:
        raise SystemExit("\n".join(failures))
    print(f"PROVENANCE_PASS: {len(mapped)} transferred files, {sum(row['status'] == 'excluded' for row in rows)} explicit exclusions")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, help="source homelab-telegram-panel checkout")
    parser.add_argument("--write", action="store_true", help="regenerate the manifest from the fixed source commit")
    args = parser.parse_args()
    if args.write and args.source is None:
        parser.error("--write requires --source")
    if args.write:
        write_manifest(args.source.resolve())
    verify(args.source.resolve() if args.source else None)


if __name__ == "__main__":
    main()

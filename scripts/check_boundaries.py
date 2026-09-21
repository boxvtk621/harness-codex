#!/usr/bin/env python3
"""Fail if the standalone Codex repository regains cross-component coupling."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
IGNORED = {".git", ".cache", "_bmad", "_bmad-output", "node_modules", "__pycache__"}
FORBIDDEN_PATH_PARTS = {
    "cursor", "panel", "router", "agentservice", "harnessclient", "harnesstunnel", "fixik"
}
FORBIDDEN_IMPORTS = (
    "github.com/boxvtk621/homelab-telegram-panel",
    "harness/adapters/cursor",
    "/internal/harnessclient",
    "/internal/harnesstunnel",
    "/internal/agentservice",
    "/internal/harnessrouter",
    "/internal/panel",
    "mobilegateway",
    "mobileauth",
    "mobilecontrollerclient",
    "components/mobile-workspace",
)
SENSITIVE_SUFFIXES = {".pem", ".key", ".crt", ".csr", ".db", ".sqlite", ".sqlite3"}
SCANNED_SUFFIXES = {".go", ".mod", ".sum", ".py", ".js", ".mjs", ".ts", ".tsx", ".sh", ".yaml", ".yml"}
SCANNED_NAMES = {"Dockerfile", "Makefile", "go.mod", "go.sum", "package.json", "package-lock.json"}
POLICY_REFERENCE_FILES = {
    Path("scripts/check_boundaries.py"),
    Path("scripts/verify_provenance.py"),
    Path(".github/workflows/quality.yml"),
}


def tracked_files():
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(part in IGNORED for part in path.relative_to(ROOT).parts):
            continue
        yield path


def main():
    failures = []
    for path in tracked_files():
        relative = path.relative_to(ROOT)
        if path.is_symlink():
            failures.append(f"repository symlink is not allowed: {relative}")
            continue
        lowered = {part.lower() for part in relative.parts}
        if lowered & FORBIDDEN_PATH_PARTS:
            failures.append(f"forbidden component path: {relative}")
        if path.suffix.lower() in SENSITIVE_SUFFIXES or path.name in {".env", "go.work"}:
            failures.append(f"forbidden secret/state/workspace file: {relative}")
        if relative in POLICY_REFERENCE_FILES or (path.suffix.lower() not in SCANNED_SUFFIXES and path.name not in SCANNED_NAMES):
            continue
        text = path.read_text(encoding="utf-8", errors="strict")
        for forbidden in FORBIDDEN_IMPORTS:
            if forbidden in text:
                failures.append(f"forbidden import/module reference in {relative}: {forbidden}")
    go_mod = (ROOT / "go.mod").read_text(encoding="utf-8")
    if re.search(r"(?m)^\s*replace\s", go_mod):
        failures.append("go.mod contains a replace directive")
    if "module github.com/boxvtk621/harness-codex" not in go_mod:
        failures.append("go.mod module identity is not standalone")
    if failures:
        raise SystemExit("\n".join(sorted(set(failures))))
    print("BOUNDARY_PASS: standalone Codex imports, paths and repository inputs are isolated")


if __name__ == "__main__":
    main()

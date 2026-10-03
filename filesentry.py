#!/usr/bin/env python3
"""FileSentry: baseline-based file integrity monitoring for defensive use."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "1.0.0"
DEFAULT_BASELINE = ".filesentry-baseline.json"
CHUNK_SIZE = 1024 * 1024


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    """Return the SHA-256 digest of a file, reading it in bounded chunks."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def collect_files(root: Path, exclusions: list[str] | None = None) -> tuple[dict[str, dict[str, Any]], list[dict[str, str]]]:
    """Collect file metadata and hashes beneath root; skip symlinks and exclusions."""
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError(f"Scan path is not a directory: {root}")
    excluded = set(exclusions or [])
    records: dict[str, dict[str, Any]] = {}
    errors: list[dict[str, str]] = []
    for current, dirs, names in os.walk(root, followlinks=False):
        current_path = Path(current)
        dirs[:] = sorted(d for d in dirs if d not in excluded and not (current_path / d).is_symlink())
        for name in sorted(names):
            path = current_path / name
            rel = path.relative_to(root).as_posix()
            if name in excluded or rel in excluded or path.is_symlink():
                continue
            try:
                if not path.is_file():
                    continue
                stat = path.stat()
                records[rel] = {
                    "sha256": sha256_file(path),
                    "size_bytes": stat.st_size,
                }
            except (OSError, PermissionError) as exc:
                errors.append({"path": rel, "error": type(exc).__name__})
    return records, errors


def load_baseline(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read baseline {path}: {exc}") from exc
    if data.get("schema_version") != 1 or not isinstance(data.get("files"), dict):
        raise ValueError("Unsupported or invalid baseline format.")
    return data


def create_baseline(root: Path, baseline_path: Path, exclusions: list[str] | None = None) -> dict[str, Any]:
    root = root.resolve(strict=True)
    files, errors = collect_files(root, exclusions)
    payload = {
        "schema_version": 1,
        "tool": "FileSentry",
        "tool_version": VERSION,
        "created_at": utc_now(),
        "root": str(root),
        "algorithm": "sha256",
        "files": files,
        "scan_errors": errors,
    }
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    baseline_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def compare_files(baseline: dict[str, Any], current: dict[str, dict[str, Any]]) -> dict[str, Any]:
    previous = baseline["files"]
    old_paths, new_paths = set(previous), set(current)
    modified = sorted(p for p in old_paths & new_paths if previous[p].get("sha256") != current[p].get("sha256"))
    return {
        "modified": [{"path": p, "baseline_sha256": previous[p].get("sha256"), "current_sha256": current[p].get("sha256")} for p in modified],
        "deleted": [{"path": p, "baseline_sha256": previous[p].get("sha256")} for p in sorted(old_paths - new_paths)],
        "new": [{"path": p, "current_sha256": current[p].get("sha256")} for p in sorted(new_paths - old_paths)],
        "unchanged_count": sum(1 for p in old_paths & new_paths if p not in modified),
    }


def print_summary(report: dict[str, Any]) -> None:
    print(f"FileSentry scan — {report['scanned_at']}")
    print(f"Root: {report['root']}")
    print(f"Files scanned: {report['files_scanned']}")
    print(f"Unchanged: {report['unchanged_count']}")
    for category, label in (("modified", "MODIFIED"), ("deleted", "DELETED"), ("new", "NEW")):
        items = report[category]
        print(f"{label}: {len(items)}")
        for item in items:
            print(f"  [{label}] {item['path']}")
    if report["scan_errors"]:
        print(f"Scan errors: {len(report['scan_errors'])}")
        for item in report["scan_errors"]:
            print(f"  [ERROR] {item['path']}: {item['error']}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Baseline-based file integrity monitoring.")
    parser.add_argument("--version", action="version", version=f"FileSentry {VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)
    baseline_cmd = sub.add_parser("baseline", help="Create or replace a trusted baseline.")
    baseline_cmd.add_argument("--path", required=True, type=Path, help="Directory to monitor.")
    baseline_cmd.add_argument("--baseline", type=Path, default=Path(DEFAULT_BASELINE), help=f"Baseline output (default: {DEFAULT_BASELINE}).")
    baseline_cmd.add_argument("--exclude", action="append", default=[], help="Exclude a directory name or relative path; may be repeated.")
    scan_cmd = sub.add_parser("scan", help="Compare current files against a baseline.")
    scan_cmd.add_argument("--path", required=True, type=Path, help="Directory to monitor.")
    scan_cmd.add_argument("--baseline", type=Path, default=Path(DEFAULT_BASELINE), help=f"Baseline input (default: {DEFAULT_BASELINE}).")
    scan_cmd.add_argument("--report", type=Path, help="Optional JSON report output path.")
    scan_cmd.add_argument("--exclude", action="append", default=[], help="Exclude a directory name or relative path; may be repeated.")
    args = parser.parse_args(argv)
    try:
        if not args.path.exists() or not args.path.is_dir():
            raise ValueError(f"Directory does not exist or is not a directory: {args.path}")
        if args.command == "baseline":
            payload = create_baseline(args.path, args.baseline, args.exclude)
            print(f"Baseline created: {args.baseline}")
            print(f"Files recorded: {len(payload['files'])}")
            if payload["scan_errors"]:
                print(f"Files skipped due to errors: {len(payload['scan_errors'])}")
            print("Protect this baseline separately from the monitored directory.")
            return 0
        baseline = load_baseline(args.baseline)
        root = args.path.resolve()
        if Path(baseline.get("root", "")).resolve() != root:
            print("WARNING: scan path differs from the baseline root.", file=sys.stderr)
        current, errors = collect_files(args.path, args.exclude)
        comparison = compare_files(baseline, current)
        report = {
            "tool": "FileSentry",
            "tool_version": VERSION,
            "scanned_at": utc_now(),
            "root": str(root),
            "files_scanned": len(current),
            "unchanged_count": comparison["unchanged_count"],
            "modified": comparison["modified"],
            "deleted": comparison["deleted"],
            "new": comparison["new"],
            "scan_errors": errors,
        }
        print_summary(report)
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            print(f"JSON report: {args.report}")
        return 1 if any(report[k] for k in ("modified", "deleted", "new", "scan_errors")) else 0
    except (ValueError, OSError) as exc:
        print(f"FileSentry error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

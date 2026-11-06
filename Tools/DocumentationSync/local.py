#!/usr/bin/env python3
"""Offline import and private reconciliation of a local UniFi OpenAPI export."""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
from urllib.parse import urlsplit

import sync

ROOT = sync.ROOT
LOCAL = "upstream/local/network.json"
MANIFEST = "private/local-manifest.json"
RECONCILIATION = "private/reconciliation.json"
LIMIT = sync.LIMIT


def local_path(relative):
    return ROOT / relative


def normalize(path, document):
    if not isinstance(path, str) or not path.startswith("/"):
        raise ValueError("Invalid OpenAPI path")
    if path == "/v1" or path.startswith("/v1/"):
        return path
    for prefix in ("/proxy/network/integration", "/integration"):
        if path == prefix + "/v1" or path.startswith(prefix + "/v1/"):
            return path[len(prefix):]
    servers = document.get("servers", [])
    if isinstance(servers, list):
        for server in servers:
            if not isinstance(server, dict) or not isinstance(server.get("url"), str):
                continue
            base = urlsplit(server["url"]).path.rstrip("/")
            if base.endswith("/v1") and not path.startswith("/v1/"):
                return "/v1" + path
    return path


def index(document):
    records = {}
    for path, entry in document["paths"].items():
        if not isinstance(entry, dict):
            continue
        normalized = normalize(path, document)
        for method, operation in entry.items():
            if method not in sync.METHODS or not isinstance(operation, dict):
                continue
            key = f"{method.upper()} {normalized}"
            if key in records:
                raise ValueError("Ambiguous normalized operation paths")
            records[key] = sync.sha(sync.encode(operation))
    return records


def compute(public, local):
    public_ops = index(public)
    local_ops = index(local)
    common = public_ops.keys() & local_ops.keys()
    if not common:
        raise ValueError("No matching operations: confirm that this is a UniFi Network Integration API spec")
    public_schemas = {item["name"]: item["fingerprint"] for item in sync.inventory(public)["schemas"]}
    local_schemas = {item["name"]: item["fingerprint"] for item in sync.inventory(local)["schemas"]}

    def compare(first, second):
        overlap = first.keys() & second.keys()
        return {
            "public_only": sorted(first.keys() - second.keys()),
            "local_only": sorted(second.keys() - first.keys()),
            "different": sorted(k for k in overlap if first[k] != second[k]),
            "identical_count": sum(first[k] == second[k] for k in overlap),
        }

    result = {
        "operations": compare(public_ops, local_ops),
        "schemas": compare(public_schemas, local_schemas),
        "public_operation_count": len(public_ops),
        "local_operation_count": len(local_ops),
        "public_schema_count": len(public_schemas),
        "local_schema_count": len(local_schemas),
        "local_reference_issue_count": len(sync.inventory(local)["reference_errors"]),
    }
    return result


def read_local():
    manifest = json.loads(local_path(MANIFEST).read_bytes())
    if manifest.get("path") != LOCAL:
        raise ValueError("Unexpected private snapshot path")
    raw = local_path(LOCAL).read_bytes()
    if sync.sha(raw) != manifest.get("sha256"):
        raise ValueError("Local specification SHA-256 mismatch")
    return manifest, sync.parse(raw)


def report(public_manifest, local_manifest, diff):
    return {
        "public_version": public_manifest["version"],
        "public_sha256": public_manifest["sha256"],
        "local_sha256": local_manifest["sha256"],
        "local_info_version": local_manifest["info_version"],
        "comparison": diff,
    }


def validate():
    sync.verify()
    public_manifest, public = sync.saved()
    local_manifest, local = read_local()
    expected = report(public_manifest, local_manifest, compute(public, local))
    observed = local_path(RECONCILIATION).read_bytes()
    if observed != sync.encode(expected):
        raise ValueError("Stale private reconciliation: run reconcile")
    print(f"PASS UniFi local reconciliation: {expected['comparison']['local_operation_count']} local operations")


def reconcile():
    sync.verify()
    public_manifest, public = sync.saved()
    local_manifest, local = read_local()
    result = report(public_manifest, local_manifest, compute(public, local))
    sync.write(RECONCILIATION, sync.encode(result))
    validate()


def import_file(path):
    sync.verify()
    source = Path(path).expanduser()
    if not source.is_file():
        raise ValueError("Expected a local OpenAPI JSON file")
    if source.stat().st_size > LIMIT:
        raise ValueError("Local OpenAPI file exceeds size limit")
    raw = source.read_bytes()
    if not raw or len(raw) > LIMIT:
        raise ValueError("Invalid local OpenAPI file size")
    doc = sync.parse(raw)
    public_manifest, public = sync.saved()
    result = compute(public, doc)
    info = doc.get("info", {})
    info_version = info.get("version") if isinstance(info, dict) else None
    info_version = info_version if isinstance(info_version, str) else None
    manifest = {
        "path": LOCAL,
        "sha256": sync.sha(raw),
        "acquired_utc": datetime.now(timezone.utc).isoformat(),
        "info_version": info_version,
        "source_kind": "local_file_import",
    }
    diff = report(public_manifest, manifest, result)
    sync.write(LOCAL, raw)
    sync.write(MANIFEST, sync.encode(manifest))
    sync.write(RECONCILIATION, sync.encode(diff))
    validate()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["import-local", "reconcile", "verify-local"])
    parser.add_argument("--file", help="Path to a locally exported OpenAPI JSON (import-local only)")
    args = parser.parse_args()
    if args.command == "import-local":
        if not args.file:
            parser.error("import-local requires --file")
        import_file(args.file)
    elif args.file:
        parser.error("--file is only accepted for import-local")
    elif args.command == "reconcile":
        reconcile()
    else:
        validate()


if __name__ == "__main__":
    main()

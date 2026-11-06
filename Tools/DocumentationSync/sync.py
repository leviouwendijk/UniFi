#!/usr/bin/env python3
"""Acquire and verify version-pinned UniFi Network OpenAPI contracts."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[2] / "References"
INDEX = "https://developer.ui.com/llms.txt"
VERSION = re.compile(r"https://developer\.ui\.com/network/(v\d+\.\d+\.\d+)/openapi\.json")
METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
LIMIT = 32 * 1024 * 1024


def encode(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, indent=4) + "\n").encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write(path, data):
    dest = ROOT / path
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=dest.parent, delete=False) as handle:
        temporary = Path(handle.name)
        handle.write(data)
    os.replace(temporary, dest)


def fetch(url):
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.hostname != "developer.ui.com":
        raise ValueError("Unapproved source")
    if parts.path != "/llms.txt" and not re.fullmatch(
        r"/network/v\d+\.\d+\.\d+/openapi\.json", parts.path
    ):
        raise ValueError("Unapproved source path")
    with urlopen(Request(url, headers={"User-Agent": "UniFiReferenceSync/1.0"}), timeout=30) as response:
        final = urlsplit(response.geturl())
        if final.scheme != "https" or final.hostname != parts.hostname or final.path != parts.path:
            raise ValueError("Unapproved redirect")
        data = response.read(LIMIT + 1)
    if not data or len(data) > LIMIT:
        raise ValueError("Invalid response size")
    return data


def parse(data):
    value = json.loads(data)
    if not isinstance(value, dict) or not str(value.get("openapi", "")).startswith("3."):
        raise ValueError("Not OpenAPI 3.x")
    if not isinstance(value.get("paths"), dict) or not isinstance(value.get("components", {}), dict):
        raise ValueError("Malformed OpenAPI document")
    return value


def references(document):
    pending = [document]
    while pending:
        node = pending.pop()
        if isinstance(node, dict):
            if isinstance(node.get("$ref"), str):
                yield node["$ref"]
            pending.extend(node.values())
        elif isinstance(node, list):
            pending.extend(node)


def reference_exists(document, reference):
    if not reference.startswith("#/"):
        return False
    node = document
    try:
        for token in reference[2:].split("/"):
            token = token.replace("~1", "/").replace("~0", "~")
            node = node[int(token)] if isinstance(node, list) else node[token]
        return True
    except (KeyError, IndexError, TypeError, ValueError):
        return False


def inventory(document):
    operations = []
    for path, item in sorted(document["paths"].items()):
        if not isinstance(item, dict):
            continue
        for method, operation in sorted(item.items()):
            if method in METHODS and isinstance(operation, dict):
                operations.append({"method": method.upper(), "path": path,
                                   "operation_id": operation.get("operationId"),
                                   "fingerprint": sha(encode(operation))})
    definitions = document.get("components", {}).get("schemas", {})
    schemas = [{"name": name, "fingerprint": sha(encode(value))}
               for name, value in sorted(definitions.items())] if isinstance(definitions, dict) else []
    errors = [{"reference": ref, "kind": "unresolved_internal" if ref.startswith("#/") else "external"}
              for ref in sorted(set(references(document))) if not reference_exists(document, ref)]
    return {"operations": operations, "schemas": schemas, "reference_errors": errors}


def saved():
    manifest = json.loads((ROOT / "manifests/snapshot.json").read_bytes())
    raw = (ROOT / manifest["path"]).read_bytes()
    if sha(raw) != manifest["sha256"]:
        raise ValueError("Snapshot SHA-256 mismatch")
    return manifest, parse(raw)


def report(manifest, records):
    return ("# UniFi OpenAPI contract inventory\n\n"
            f"- Version: {manifest['version']}\n"
            f"- Acquired UTC: {manifest['acquired_utc']}\n"
            f"- Operations: {len(records['operations'])}\n"
            f"- Schemas: {len(records['schemas'])}\n"
            f"- Reference issues: {len(records['reference_errors'])}\n\n"
            "Acquisition completeness does not prove live API compatibility.\n").encode()


def drift(before, after, key):
    old = {key(item): item["fingerprint"] for item in before}
    new = {key(item): item["fingerprint"] for item in after}
    return {"added": sorted(new.keys() - old.keys()),
            "removed": sorted(old.keys() - new.keys()),
            "modified": sorted(k for k in old.keys() & new.keys() if old[k] != new[k])}


def publish(manifest, records, change=None):
    write("manifests/snapshot.json", encode(manifest))
    for category, contents in records.items():
        write(f"inventories/{category}.json", encode(contents))
    write("inventories/coverage.md", report(manifest, records))
    if change is not None:
        write("inventories/drift.json", encode(change))


def verify():
    manifest, document = saved()
    records = inventory(document)
    for category, contents in records.items():
        if (ROOT / f"inventories/{category}.json").read_bytes() != encode(contents):
            raise ValueError(f"Stale inventory: {category}")
    if (ROOT / "inventories/coverage.md").read_bytes() != report(manifest, records):
        raise ValueError("Stale coverage report")
    if not (ROOT / "inventories/drift.json").is_file():
        raise ValueError("Missing drift report")
    print(f"PASS UniFi contract: {len(records['operations'])} operations, {len(records['schemas'])} schemas")


def sync(version):
    if version is None:
        candidates = VERSION.findall(fetch(INDEX).decode("utf-8"))
        if not candidates:
            raise ValueError("No Network OpenAPI version in developer index")
        version = max(set(candidates), key=lambda v: tuple(map(int, v[1:].split("."))))
    if not re.fullmatch(r"v\d+\.\d+\.\d+", version):
        raise ValueError("Invalid Network version")
    url = f"https://developer.ui.com/network/{version}/openapi.json"
    raw = fetch(url)
    document = parse(raw)
    previous = inventory(saved()[1]) if (ROOT / "manifests/snapshot.json").exists() else None
    records = inventory(document)
    change = {"kind": "changed" if previous else "baseline"}
    for category, key in (("operations", lambda x: f"{x['method']} {x['path']}"),
                          ("schemas", lambda x: x["name"])):
        change[category] = drift(previous[category], records[category], key) if previous else {
            "added": [], "removed": [], "modified": []}
    path = f"upstream/public/network-{version}.json"
    manifest = {"version": version, "source_url": url, "path": path,
                "sha256": sha(raw), "acquired_utc": datetime.now(timezone.utc).isoformat()}
    write(path, raw)
    publish(manifest, records, change)
    verify()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["sync", "rebuild", "audit", "verify"])
    parser.add_argument("--version", help="Explicit upstream Network version, e.g. v11.0.97")
    args = parser.parse_args()
    if args.command == "sync":
        sync(args.version)
    elif args.command == "rebuild":
        manifest, document = saved()
        publish(manifest, inventory(document))
        verify()
    else:
        verify()


if __name__ == "__main__":
    main()

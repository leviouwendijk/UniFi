# UniFi Network documentation acquisition

From the UniFi package root:

- `python3 Tools/DocumentationSync/sync.py sync`: use the newest OpenAPI version found in Ubiquiti's official `llms.txt` index.
- `python3 Tools/DocumentationSync/sync.py sync --version v11.0.97`: request a specific public version, even if its index entry has not appeared yet.
- `python3 Tools/DocumentationSync/sync.py rebuild`: regenerate derived inventories offline.
- `python3 Tools/DocumentationSync/sync.py audit`: verify source checksums and derived inventory consistency, read-only.
- `python3 Tools/DocumentationSync/sync.py verify`: same integrity verification.
- `python3 -m unittest discover -s Tools/DocumentationSync -p 'test_*.py'`: run fixture tests without network access.

The source is exclusively HTTPS `developer.ui.com`; no credentials or controller access are used. A subsequent pass can ingest a locally exported Network OpenAPI JSON from UniFi Network > Integrations, store it in a Git-ignored private location and reconcile it with the public baseline without contaminating version-controlled references. Neither the documentation tooling nor the package should store actual network configuration or API keys.


## Local contract import (offline)

Export the UniFi Network Integration OpenAPI JSON to a local file, then run:

- `python3 Tools/DocumentationSync/local.py import-local --file /path/to/integration.json`
- `python3 Tools/DocumentationSync/local.py reconcile` after updating the public spec.
- `python3 Tools/DocumentationSync/local.py verify-local` to check checksums and reconciliation freshness.

These commands make no controller or network requests. Local specifications, manifests and diff reports remain under Git-ignored `References/upstream/local/` and `References/private/`. Console output contains counts only; never send the imported specification or its private report to a remote agent. A matching operation proves only contract similarity, not live endpoint availability.

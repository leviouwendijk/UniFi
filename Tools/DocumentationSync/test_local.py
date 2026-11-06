import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import local
import sync


class LocalDocumentationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name) / "References"
        root.mkdir()
        self.root_patch = patch.object(local, "ROOT", root)
        self.sync_patch = patch.object(sync, "ROOT", root)
        self.root_patch.start()
        self.sync_patch.start()
        self.addCleanup(self.root_patch.stop)
        self.addCleanup(self.sync_patch.stop)

        self.public = {
            "openapi": "3.0.3",
            "paths": {"/v1/sites": {"get": {"operationId": "getSites"}}},
            "components": {"schemas": {"Site": {"type": "object"}}},
        }
        self.local = {
            "openapi": "3.0.3",
            "servers": [{"url": "https://example.invalid/proxy/network/integration/v1"}],
            "info": {"version": "11.0.97"},
            "paths": {"/sites": {"get": {"operationId": "getSites"}}},
            "components": {"schemas": {"Site": {"type": "object"}}},
        }
        raw = sync.encode(self.public)
        public_path = "upstream/public/network-fixture.json"
        manifest = {"path": public_path, "sha256": sync.sha(raw), "version": "fixture",
                    "acquired_utc": "2026-11-06T00:00:00Z"}
        sync.write(public_path, raw)
        sync.publish(manifest, sync.inventory(self.public), {"kind": "baseline"})
        self.input_path = root.parent / "export.json"
        self.input_path.write_bytes(sync.encode(self.local))

    def test_import_and_verify(self):
        local.import_file(self.input_path)
        local.validate()
        diff = json.loads(local.local_path(local.RECONCILIATION).read_bytes())
        self.assertEqual(diff["comparison"]["operations"]["identical_count"], 1)
        self.assertEqual(diff["comparison"]["operations"]["public_only"], [])
        self.assertNotIn("example.invalid", json.dumps(diff))

    def test_import_rejects_incompatible_contract(self):
        self.local["paths"] = {"/unrelated": {"get": {}}}
        self.input_path.write_bytes(sync.encode(self.local))
        with self.assertRaisesRegex(ValueError, "No matching operations"):
            local.import_file(self.input_path)
        self.assertFalse(local.local_path(local.MANIFEST).exists())

    def test_tampered_local_rejected(self):
        local.import_file(self.input_path)
        local.local_path(local.LOCAL).write_bytes(b"{}")
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            local.validate()

    def test_reconcile_after_public_change(self):
        local.import_file(self.input_path)
        new_public = dict(self.public)
        new_public["paths"] = {**self.public["paths"], "/v1/info": {"get": {}}}
        raw = sync.encode(new_public)
        public_path = "upstream/public/network-fixture.json"
        manifest = {"path": public_path, "sha256": sync.sha(raw), "version": "fixture",
                    "acquired_utc": "2026-11-06T00:00:00Z"}
        sync.write(public_path, raw)
        sync.publish(manifest, sync.inventory(new_public))
        with self.assertRaisesRegex(ValueError, "Stale private reconciliation"):
            local.validate()
        local.reconcile()
        result = json.loads(local.local_path(local.RECONCILIATION).read_bytes())
        self.assertEqual(result["comparison"]["operations"]["public_only"], ["GET /v1/info"])

    def test_prefix_handling(self):
        path = "/proxy/network/integration/v1/sites"
        self.assertEqual(local.normalize(path, {}), "/v1/sites")
        self.assertEqual(local.normalize("/v1/sites", {}), "/v1/sites")

    def test_public_reference_not_modified_by_import(self):
        before = local.local_path("manifests/snapshot.json").read_bytes()
        local.import_file(self.input_path)
        self.assertEqual(before, local.local_path("manifests/snapshot.json").read_bytes())


if __name__ == "__main__":
    unittest.main()

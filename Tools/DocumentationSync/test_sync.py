import unittest

from sync import drift, inventory, reference_exists, parse


class DocumentationTests(unittest.TestCase):
    def setUp(self):
        self.spec = {"openapi": "3.1.0", "paths": {"/v1/sites": {
            "get": {"operationId": "listSites", "responses": {
                "200": {"$ref": "#/components/schemas/Reply"}}}}},
            "components": {"schemas": {"Reply": {"type": "object"}}}}

    def test_contract_inventory(self):
        result = inventory(self.spec)
        self.assertEqual(result["operations"][0]["path"], "/v1/sites")
        self.assertEqual(len(result["schemas"]), 1)
        self.assertEqual(result["reference_errors"], [])

    def test_bad_reference_reported(self):
        self.spec["paths"]["/v1/sites"]["get"]["responses"]["200"]["$ref"] = "#/missing"
        self.assertEqual(inventory(self.spec)["reference_errors"][0]["kind"], "unresolved_internal")

    def test_pointer_escaping(self):
        self.assertTrue(reference_exists({"a/b": True}, "#/a~1b"))

    def test_version_rejection(self):
        with self.assertRaises(ValueError):
            parse(b'{"paths":{}}')

    def test_semantic_drift(self):
        before = [{"name": "A", "fingerprint": "1"}]
        after = [{"name": "A", "fingerprint": "2"}, {"name": "B", "fingerprint": "3"}]
        self.assertEqual(drift(before, after, lambda x: x["name"]), {
            "added": ["B"], "removed": [], "modified": ["A"]})


if __name__ == "__main__":
    unittest.main()

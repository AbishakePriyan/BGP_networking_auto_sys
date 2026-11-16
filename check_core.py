"""Offline checks. Does not claim to validate Docker/FRR integration."""
import json
import unittest
from core import ROOT, extract, filter_commands, parse_routes


class CoreChecks(unittest.TestCase):
    registry = json.loads((ROOT / "authorized_prefixes.json").read_text())

    def test_features(self):
        good = {"prefix": "203.0.113.0/25", "origin_as": 65001, "as_path": [65001]}
        bad = {**good, "origin_as": 65003, "as_path": [65003]}
        self.assertEqual(extract(good, self.registry)["origin_mismatch"], 0)
        self.assertEqual(extract(bad, self.registry)["origin_mismatch"], 1)
        self.assertEqual(extract(bad, self.registry)["prefix_length_delta"], 1)

    def test_unknown_is_not_attack(self):
        route = {"prefix": "198.51.100.0/24", "origin_as": 65003, "as_path": [65003]}
        self.assertIsNone(extract(route, self.registry))

    def test_json_parsing(self):
        fixture = {"routes": {"203.0.113.0/25": [{"path": "65003", "nexthops": [{"ip": "172.30.77.4"}]}]}}
        self.assertEqual(parse_routes(fixture)[0]["origin_as"], 65003)
        self.assertEqual(parse_routes(fixture)[0]["peer"], "172.30.77.4")

    def test_filter_scope(self):
        commands = filter_commands("172.30.77.4", "203.0.113.0/25")
        self.assertTrue(any("BLOCK-R3" in item and "permit 203.0.113.0/25" in item for item in commands))
        self.assertEqual(commands[-1], "clear bgp 172.30.77.4 soft in")
        with self.assertRaises(ValueError):
            filter_commands("172.30.77.99", "203.0.113.0/25")
        with self.assertRaises(ValueError):
            filter_commands("172.30.77.4", "8.8.8.0/24")


if __name__ == "__main__":
    unittest.main()

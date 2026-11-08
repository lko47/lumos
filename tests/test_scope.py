from __future__ import annotations

import unittest

from lumos.core.scope import ScopeRule, is_target_in_scope, parse_scope_rule, parse_target


class ScopeGuardTests(unittest.TestCase):
    def test_ip_and_cidr_are_checked_by_containment(self) -> None:
        rules = [parse_scope_rule("192.0.2.0/24", included=True)]
        self.assertTrue(is_target_in_scope("192.0.2.22", rules).allowed)
        self.assertTrue(is_target_in_scope("192.0.2.128/25", rules).allowed)
        self.assertFalse(is_target_in_scope("192.0.3.0/24", rules).allowed)

    def test_union_of_scope_prefixes_covers_target_without_expansion(self) -> None:
        rules = [
            parse_scope_rule("198.51.100.0/25", included=True),
            parse_scope_rule("198.51.100.128/25", included=True),
        ]
        self.assertTrue(is_target_in_scope("198.51.100.0/24", rules).allowed)
        self.assertTrue(is_target_in_scope("0.0.0.0/0", [parse_scope_rule("0.0.0.0/0", included=True)]).allowed)

    def test_any_overlap_with_exclusion_blocks_target(self) -> None:
        rules = [
            parse_scope_rule("192.0.2.0/24", included=True),
            parse_scope_rule("192.0.2.64/26", included=False),
        ]
        self.assertTrue(is_target_in_scope("192.0.2.1/32", rules).allowed)
        self.assertFalse(is_target_in_scope("192.0.2.0/25", rules).allowed)

    def test_ranges_are_checked_as_intervals(self) -> None:
        rules = [parse_scope_rule("192.0.2.0-192.0.2.20", included=True)]
        self.assertTrue(is_target_in_scope("192.0.2.2-192.0.2.19", rules).allowed)
        self.assertFalse(is_target_in_scope("192.0.2.20-192.0.2.21", rules).allowed)

    def test_hostname_requires_an_exact_allow_rule(self) -> None:
        rules = [parse_scope_rule("app.example.invalid", included=True)]
        self.assertTrue(is_target_in_scope("APP.example.invalid.", rules).allowed)
        self.assertFalse(is_target_in_scope("other.example.invalid", rules).allowed)

    def test_ipv4_and_ipv6_families_do_not_mix(self) -> None:
        rules = [parse_scope_rule("2001:db8::/32", included=True)]
        self.assertTrue(is_target_in_scope("2001:db8::10", rules).allowed)
        self.assertFalse(is_target_in_scope("192.0.2.10", rules).allowed)

    def test_malformed_ranges_and_hostnames_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            parse_target("192.0.2.9-192.0.2.1")
        with self.assertRaises(ValueError):
            parse_target("*.example.invalid")


if __name__ == "__main__":
    unittest.main()

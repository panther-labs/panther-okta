import unittest

from panther_config import detection
import panther_okta as okta


class TestRules(unittest.TestCase):
    def test_account_support_access_defaults(self):
        rule = okta.rules.account_support_access()

        self.assertIsInstance(rule, detection.Rule)
        self.assertEqual(rule.rule_id, "Okta.Support.Access")

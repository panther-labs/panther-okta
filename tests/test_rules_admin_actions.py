import unittest

from panther_config import detection
import panther_okta as okta


class TestRulesAdminActions(unittest.TestCase):
    def test_admin_disabled_mfa(self):
        name_override = "Override Name"
        rule = okta.rules.admin_disabled_mfa(
            detection.RuleOptions(name=name_override)
        )

        self.assertIsInstance(rule, detection.Rule)
        self.assertEqual(rule.name, name_override)

    def test_admin_role_assigned(self):
        name_override = "Override Name"
        rule = okta.rules.admin_role_assigned(
            detection.RuleOptions(name=name_override)
        )

        self.assertIsInstance(rule, detection.Rule)
        self.assertEqual(rule.name, name_override)

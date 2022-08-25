from . import rules, sample_logs

__all__ = [
    "use_all_with_defaults",
    "rules",
    "sample_logs",
]


def use_all_with_defaults() -> None:
    rules.account_support_access()
    rules.admin_disabled_mfa()
    rules.admin_role_assigned()
    rules.api_key_created()
    rules.brute_force_logins()
    # rules.geo_improbable_access()
    rules.support_reset()

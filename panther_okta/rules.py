from typing import List, Optional

from panther_config import detection
from panther_utils import (
    PantherEvent,
    match_filters,
    standard_tags,
)

from . import sample_logs

from ._shared import (
    SYSTEM_LOG_TYPE,
    SHARED_TAGS,
    SUPPORT_ACCESS_EVENTS,
    SUPPORT_RESET_EVENTS,
    create_alert_context,
    SHARED_SUMMARY_ATTRS,
)

__all__ = [
    "account_support_access",
    "admin_disabled_mfa",
    "admin_role_assigned",
    "api_key_created",
    "api_key_revoked",
    "brute_force_logins",
    # "geo_improbable_access",
    "support_reset",
]


def _tags(*extra_tags: str) -> List[str]:
    return [*SHARED_TAGS, *extra_tags]


def _account_support_access_title(event: PantherEvent) -> str:
    return f"Okta Support Access Granted by {event.udm('actor_user')}"


def account_support_access(
    overrides: detection.RuleOptions = detection.RuleOptions(),
) -> detection.Rule:
    """Detects when an admin user has granted access to Okta Support for your account"""

    return detection.Rule(
        name=(overrides.name or "Okta Support Access Granted"),
        rule_id=(overrides.rule_id or "Okta.Support.Access"),
        log_types=(overrides.log_types or [SYSTEM_LOG_TYPE]),
        tags=(
            overrides.tags
            or _tags(standard_tags.DATA_MODEL, "Initial Access:Trusted Relationship")
        ),
        reports=(overrides.reports or {detection.ReportKeyMITRE: ["TA0001:T1199"]}),
        severity=(overrides.severity or detection.SeverityMedium),
        description=(
            overrides.description
            or "An admin user has granted access to Okta Support to your account"
        ),
        reference=(
            overrides.reference
            or "https://help.okta.com/en/prod/Content/Topics/Settings/settings-support-access.htm"
        ),
        runbook=(
            overrides.runbook or "Contact Admin to ensure this was sanctioned activity"
        ),
        filters=(
            overrides.filters
            or [
                match_filters.deep_in("eventType", SUPPORT_ACCESS_EVENTS),
            ]
        ),
        alert_title=(overrides.alert_title or _account_support_access_title),
        alert_context=(overrides.alert_context or create_alert_context),
        summary_attrs=(overrides.summary_attrs or SHARED_SUMMARY_ATTRS),
        unit_tests=(
            overrides.unit_tests
            or [
                detection.JSONUnitTest(
                    name="Support Access Granted",
                    expect_match=True,
                    data=sample_logs.user_session_impersonation_grant,
                ),
                detection.JSONUnitTest(
                    name="Login Event",
                    expect_match=False,
                    data=sample_logs.user_session_start,
                ),
            ]
        ),
    )


def _admin_disabled_mfa_title(event: PantherEvent) -> str:
    return f"Okta System-wide MFA Disabled by Admin User {event.udm('actor_user')}"


def admin_disabled_mfa(
    overrides: detection.RuleOptions = detection.RuleOptions(),
) -> detection.Rule:
    """An admin user has disabled the MFA requirement for your Okta account"""

    return detection.Rule(
        name=(overrides.name or "Okta MFA Globally Disabled"),
        rule_id=(overrides.rule_id or "Okta.Global.MFA.Disabled"),
        log_types=(overrides.log_types or [SYSTEM_LOG_TYPE]),
        tags=(
            overrides.tags
            or _tags(
                standard_tags.DATA_MODEL,
                "Defense Evasion:Modify Authentication Process",
            )
        ),
        reports=(overrides.reports or {detection.ReportKeyMITRE: ["TA0005:T1556"]}),
        severity=(overrides.severity or detection.SeverityHigh),
        description=(
            overrides.description
            or "An admin user has disabled the MFA requirement for your Okta account"
        ),
        reference=(
            overrides.reference
            or "https://developer.okta.com/docs/reference/api/event-types/?q=system.mfa.factor.deactivate"
        ),
        runbook=(
            overrides.runbook or "Contact Admin to ensure this was sanctioned activity"
        ),
        filters=(
            overrides.filters
            or [
                match_filters.deep_equal("eventType", SUPPORT_ACCESS_EVENTS),
            ]
        ),
        alert_title=(overrides.alert_title or _admin_disabled_mfa_title),
        alert_context=(overrides.alert_context or create_alert_context),
        summary_attrs=(overrides.summary_attrs or SHARED_SUMMARY_ATTRS),
        unit_tests=(
            overrides.unit_tests
            or [
                detection.JSONUnitTest(
                    name="MFA Disabled",
                    expect_match=True,
                    data=sample_logs.system_mfa_factor_deactivate,
                ),
                detection.JSONUnitTest(
                    name="Login Event",
                    expect_match=False,
                    data=sample_logs.user_session_start,
                ),
            ]
        ),
    )


def _admin_role_assigned_title(event: PantherEvent) -> str:
    from panther_base_helpers import deep_get  # type: ignore

    target = event.get("target", [{}])
    display_name = (
        target[0].get("displayName", "MISSING DISPLAY NAME") if target else ""
    )
    alternate_id = (
        target[0].get("alternateId", "MISSING ALTERNATE ID") if target else ""
    )
    privilege = deep_get(
        event,
        "debugContext",
        "debugData",
        "privilegeGranted",
        default="<UNKNOWN_PRIVILEGE>",
    )

    return (
        f"{deep_get(event, 'actor', 'displayName')} "
        f"<{deep_get(event, 'actor', 'alternateId')}> granted "
        f"[{privilege}] privileges to {display_name} <{alternate_id}>"
    )


def _admin_role_assigned_severity(event: PantherEvent) -> str:
    from panther_base_helpers import deep_get  # type: ignore

    if (
        deep_get(event, "debugContext", "debugData", "privilegeGranted")
        == "Super administrator"
    ):
        return "HIGH"
    return "INFO"


def admin_role_assigned(
    overrides: detection.RuleOptions = detection.RuleOptions(),
) -> detection.Rule:
    """A user has been granted administrative privileges in Okta"""

    return detection.Rule(
        name=(overrides.name or "Okta Admin Role Assigned"),
        rule_id=(overrides.rule_id or "Okta.AdminRoleAssigned"),
        log_types=(overrides.log_types or [SYSTEM_LOG_TYPE]),
        tags=(
            overrides.tags
            or _tags(
                standard_tags.DATA_MODEL,
                "Privilege Escalation:Valid Accounts",
            )
        ),
        reports=(overrides.reports or {detection.ReportKeyMITRE: ["TA0004:T1078"]}),
        severity=(
            overrides.severity
            or detection.DynamicStringField(
                func=_admin_role_assigned_severity,
                fallback=detection.SeverityInfo,
            )
        ),
        description=(
            overrides.description
            or "A user has been granted administrative privileges in Okta"
        ),
        reference=(
            overrides.reference
            or "https://help.okta.com/en/prod/Content/Topics/Security/administrators-admin-comparison.htm"
        ),
        runbook=(
            overrides.runbook
            or "Reach out to the user if needed to validate the activity"
        ),
        filters=(
            overrides.filters
            or [
                match_filters.deep_equal("eventType", "user.account.privilege.grant"),
                match_filters.deep_equal("outcome.result", "SUCCESS"),
                match_filters.deep_equal(
                    "debugContext.debugData.privilegeGranted", r"[aA]dministrator"
                ),
            ]
        ),
        alert_title=(overrides.alert_title or _admin_role_assigned_title),
        alert_context=(overrides.alert_context or create_alert_context),
        summary_attrs=(overrides.summary_attrs or SHARED_SUMMARY_ATTRS),
        unit_tests=(
            overrides.unit_tests
            or [
                detection.JSONUnitTest(
                    name="Admin Access Assigned",
                    expect_match=True,
                    data=sample_logs.admin_access_assigned,
                ),
            ]
        ),
    )


def _api_key_created_title(event: PantherEvent) -> str:
    from panther_base_helpers import deep_get  # type: ignore

    target = event.get("target", [{}])
    key_name = (
        target[0].get("displayName", "MISSING DISPLAY NAME")
        if target
        else "MISSING TARGET"
    )

    return (
        f"{deep_get(event, 'actor', 'displayName')} <{deep_get(event, 'actor', 'alternateId')}>"
        f"created a new API key - <{key_name}>"
    )


def api_key_created(
    overrides: detection.RuleOptions = detection.RuleOptions(),
) -> detection.Rule:
    """A user created an API Key in Okta"""

    return detection.Rule(
        name=(overrides.name or "Okta API Key Created"),
        rule_id=(overrides.rule_id or "Okta.APIKeyCreated"),
        log_types=(overrides.log_types or [SYSTEM_LOG_TYPE]),
        tags=(
            overrides.tags
            or _tags(
                "Credential Access:Steal Application Access Token",
            )
        ),
        reports=(overrides.reports or {detection.ReportKeyMITRE: ["TA0006:T1528"]}),
        severity=(overrides.severity or detection.SeverityInfo),
        description=(overrides.description or "A user created an API Key in Okta"),
        reference=(
            overrides.reference
            or "https://help.okta.com/en/prod/Content/Topics/Security/API.htm"
        ),
        runbook=(
            overrides.runbook
            or "Reach out to the user if needed to validate the activity."
        ),
        filters=(
            overrides.filters
            or [
                match_filters.deep_equal("eventType", "system.api_token.create"),
                match_filters.deep_equal("outcome.result", "SUCCESS"),
            ]
        ),
        alert_title=(overrides.alert_title or _api_key_created_title),
        alert_context=(overrides.alert_context or create_alert_context),
        summary_attrs=(overrides.summary_attrs or SHARED_SUMMARY_ATTRS),
        unit_tests=(
            overrides.unit_tests
            or [
                detection.JSONUnitTest(
                    name="API Key Created",
                    expect_match=True,
                    data=sample_logs.system_api_token_create,
                ),
            ]
        ),
    )


def _api_key_revoked_title(event: PantherEvent) -> str:
    target = event.get("target", [{}])
    key_name = (
        target[0].get("displayName", "MISSING DISPLAY NAME")
        if target
        else "MISSING TARGET"
    )

    return (
        f"{event.get('actor', {}).get('displayName')} <{event.get('actor', {}).get('alternateId')}>"
        f"revoked API key - <{key_name}>"
    )


def api_key_revoked(
    overrides: detection.RuleOptions = detection.RuleOptions(),
) -> detection.Rule:
    """A user has revoked an API Key in Okta"""

    return detection.Rule(
        name=(overrides.name or "Okta API Key Revoked"),
        rule_id=(overrides.rule_id or "Okta.APIKeyRevoked"),
        log_types=(overrides.log_types or [SYSTEM_LOG_TYPE]),
        tags=(overrides.tags or _tags()),
        severity=(overrides.severity or detection.SeverityInfo),
        description=(overrides.description or "A user has revoked an API Key in Okta"),
        reference=(
            overrides.reference
            or "https://help.okta.com/en/prod/Content/Topics/Security/API.htm"
        ),
        runbook=(overrides.runbook or "Validate this action was authorized."),
        filters=(
            overrides.filters
            or [
                match_filters.deep_equal("eventType", "system.api_token.revoke"),
                match_filters.deep_equal("outcome.result", "SUCCESS"),
            ]
        ),
        alert_title=(overrides.alert_title or _api_key_revoked_title),
        alert_context=(overrides.alert_context or create_alert_context),
        summary_attrs=(overrides.summary_attrs or SHARED_SUMMARY_ATTRS),
        unit_tests=(
            overrides.unit_tests
            or [
                detection.JSONUnitTest(
                    name="API Key Revoked",
                    expect_match=True,
                    data=sample_logs.system_api_token_revoke,
                ),
            ]
        ),
    )


def _brute_force_logins_title(event: PantherEvent) -> str:
    return (
        f"Suspected brute force Okta logins to account "
        f"{event.get('actor', {}).get('alternateId', '<UNKNOWN_ACCOUNT>')}, due to "
        f"[{event.get('outcome', {}).get('reason', '<UNKNOWN_REASON>')}]"
    )


def brute_force_logins(
    overrides: detection.RuleOptions = detection.RuleOptions(),
) -> detection.Rule:
    """DESCRIPTION"""

    return detection.Rule(
        name=(overrides.name or ""),
        rule_id=(overrides.rule_id or ""),
        log_types=(overrides.log_types or [SYSTEM_LOG_TYPE]),
        tags=(overrides.tags or _tags()),
        severity=(overrides.severity or detection.SeverityInfo),
        description=(overrides.description or ""),
        reference=(overrides.reference or ""),
        runbook=(overrides.runbook or ""),
        filters=(
            overrides.filters
            or [
                match_filters.deep_equal("eventType", "user.session.start"),
                match_filters.deep_equal("outcome.result", "FAILURE"),
            ]
        ),
        alert_title=(overrides.alert_title or _brute_force_logins_title),
        alert_context=(overrides.alert_context or create_alert_context),
        summary_attrs=(overrides.summary_attrs or SHARED_SUMMARY_ATTRS),
        unit_tests=(
            overrides.unit_tests
            or [
                detection.JSONUnitTest(
                    name="",
                    expect_match=True,
                    data="",
                ),
            ]
        ),
    )


# def geo_improbable_access(
#     overrides: detection.RuleOptions = detection.RuleOptions(),
# ) -> detection.Rule:
#     """DESCRIPTION"""
#
#     return detection.Rule(
#         name=(overrides.name or ""),
#         rule_id=(overrides.rule_id or ""),
#         log_types=(overrides.log_types or [SYSTEM_LOG_TYPE]),
#         tags=(
#             overrides.tags
#             or _tags()
#         ),
#         severity=(
#             overrides.severity
#             or detection.SeverityInfo
#         ),
#         description=(
#             overrides.description
#             or ""
#         ),
#         reference=(
#             overrides.reference
#             or ""
#         ),
#         runbook=(
#             overrides.runbook
#             or ""
#         ),
#         filters=(
#             overrides.filters
#             or [
#                 match_filters.deep_equal("eventType", "system.api_token.revoke"),
#                 match_filters.deep_equal("outcome.result", "SUCCESS"),
#             ]
#         ),
#         alert_title=(overrides.alert_title or _api_key_revoked_title),
#         alert_context=(overrides.alert_context or create_alert_context),
#         summary_attrs=(overrides.summary_attrs or SHARED_SUMMARY_ATTRS),
#         unit_tests=(
#             overrides.unit_tests
#             or [
#                 detection.JSONUnitTest(
#                     name="",
#                     expect_match=True,
#                     data="",
#                 ),
#             ]
#         ),
#     )


def _support_reset_title(event: PantherEvent) -> str:
    return f"Okta Support Reset Password or MFA for user {event.udm('actor_user')}"


def support_reset(
    overrides: detection.RuleOptions = detection.RuleOptions(),
) -> detection.Rule:
    """DESCRIPTION"""

    return detection.Rule(
        name=(overrides.name or ""),
        rule_id=(overrides.rule_id or ""),
        log_types=(overrides.log_types or [SYSTEM_LOG_TYPE]),
        tags=(overrides.tags or _tags()),
        severity=(overrides.severity or detection.SeverityInfo),
        description=(overrides.description or ""),
        reference=(overrides.reference or ""),
        runbook=(overrides.runbook or ""),
        filters=(
            overrides.filters
            or [
                match_filters.deep_in("eventType", SUPPORT_RESET_EVENTS),
                match_filters.deep_equal("actor.alternateId", "system@okta.com"),
                match_filters.deep_equal("transaction.id", "unknown"),
                match_filters.deep_equal("userAgent.rawUserAgent", None),
                match_filters.deep_equal("client.geographicalContext.country", None),
            ]
        ),
        alert_title=(overrides.alert_title or _support_reset_title),
        alert_context=(overrides.alert_context or create_alert_context),
        summary_attrs=(overrides.summary_attrs or SHARED_SUMMARY_ATTRS),
        unit_tests=(
            overrides.unit_tests
            or [
                detection.JSONUnitTest(
                    name="",
                    expect_match=True,
                    data="",
                ),
            ]
        ),
    )

from panther_config import detection
from panther_okta import sample_logs

from panther_okta._shared import (
    rule_tags,
    standard_tags,
    SYSTEM_LOG_TYPE,
    create_alert_context,
    SHARED_SUMMARY_ATTRS,
    SUPPORT_ACCESS_EVENTS,
)

from panther_utils import (
    PantherEvent,
    match_filters,
)

__all__ = [
    "admin_disabled_mfa",
    "admin_role_assigned",
]


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
            or rule_tags(
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
            or rule_tags(
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
from panther_config import detection
from panther_okta import sample_logs

from panther_okta._shared import (
    rule_tags,
    standard_tags,
    SYSTEM_LOG_TYPE,
    SHARED_SUMMARY_ATTRS,
    SUPPORT_ACCESS_EVENTS,
    SUPPORT_RESET_EVENTS,
    create_alert_context,
)

from panther_utils import (
    PantherEvent,
    match_filters,
)

__all__ = [
    "account_support_access",
    "support_reset",
]


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
            or rule_tags(
                standard_tags.DATA_MODEL, "Initial Access:Trusted Relationship"
            )
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
        tags=(overrides.tags or rule_tags()),
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

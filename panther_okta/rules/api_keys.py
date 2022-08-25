from panther_config import detection
from panther_okta import sample_logs

from panther_okta._shared import (
    rule_tags,
    SYSTEM_LOG_TYPE,
    SHARED_SUMMARY_ATTRS,
    create_alert_context,
)

from panther_utils import (
    PantherEvent,
    match_filters,
)

__all__ = [
    "api_key_created",
    "api_key_revoked",
]


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
            or rule_tags(
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
        tags=(overrides.tags or rule_tags()),
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
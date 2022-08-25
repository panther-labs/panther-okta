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

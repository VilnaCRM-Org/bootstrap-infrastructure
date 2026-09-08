#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import _github_repository_controls as _repository_controls
import _well_architected_alert_route_observation as _alert_route_observation
import _well_architected_aws_alert_route as _aws_alert_route
import _well_architected_aws_cloudtrail as _aws_cloudtrail
import _well_architected_aws_cost_evidence as _aws_cost_evidence
import _well_architected_aws_iam_access as _aws_iam_access
import _well_architected_aws_metadata as _aws_metadata
import _well_architected_dependabot_evidence as _dependabot_evidence
import _well_architected_env as _env
import _well_architected_evidence_common as _evidence_common
import _well_architected_github_local_state as _github_local_state
import _well_architected_github_pr_checks as _github_pr_checks_evidence
import _well_architected_github_repository_evidence as _github_repository_evidence
import _well_architected_github_review_threads as _github_review_threads
import _well_architected_github_rollup as _github_rollup
import _well_architected_markdown as _markdown
import _well_architected_repository_fanout_evidence as _repository_fanout_evidence
import _well_architected_restore_evidence as _restore_evidence
import _well_architected_scoring as _scoring
import _well_architected_security_account_evidence as _security_account_evidence
import _well_architected_structured_evidence as _structured_evidence
from _script_support import repo_root, run

ROOT_DIR = repo_root(__file__)
DEFAULT_REQUIRED_STATUS_CHECKS = _repository_controls.REQUIRED_STATUS_CHECKS
_active_branch_ruleset_count = _repository_controls.active_branch_ruleset_count
_ruleset_required_status_check_contexts = (
    _repository_controls.required_status_contexts_for_rulesets
)
_ruleset_has_pull_request_reviews = _repository_controls.rulesets_have_pull_request_rule
_all_blockers = _markdown.all_blockers
_markdown_checks = _markdown.markdown_checks
_markdown_cell = _markdown.markdown_cell
_markdown_string_entries = _markdown.markdown_string_entries
_markdown_text = _markdown.markdown_text
_markdown_value = _markdown.markdown_value
BLOCKING_DEPENDABOT_SEVERITIES = _dependabot_evidence.BLOCKING_DEPENDABOT_SEVERITIES
DEFAULT_DEPENDABOT_DEPENDENCY = _dependabot_evidence.DEFAULT_DEPENDABOT_DEPENDENCY
DEFAULT_DEPENDABOT_MANIFEST = _dependabot_evidence.DEFAULT_DEPENDABOT_MANIFEST
DEPENDABOT_ALL_DEPENDENCIES = _dependabot_evidence.DEPENDABOT_ALL_DEPENDENCIES
DEPENDABOT_EXCEPTION_ALLOWED_APPROVALS = (
    _dependabot_evidence.DEPENDABOT_EXCEPTION_ALLOWED_APPROVALS
)
DEPENDABOT_EXCEPTION_REQUIRED_FIELDS = (
    _dependabot_evidence.DEPENDABOT_EXCEPTION_REQUIRED_FIELDS
)
DependabotAlertRequest = _dependabot_evidence.DependabotAlertRequest
_alert_number_text = _dependabot_evidence._alert_number_text
_dependabot_alert_blockers = _dependabot_evidence._dependabot_alert_blockers
_dependabot_alert_number = _dependabot_evidence._dependabot_alert_number
_dependabot_alert_numbers = _dependabot_evidence._dependabot_alert_numbers
_dependabot_exception_alert_number_blockers = (
    _dependabot_evidence._dependabot_exception_alert_number_blockers
)
_dependabot_exception_alert_numbers = (
    _dependabot_evidence._dependabot_exception_alert_numbers
)
_dependabot_exception_payload_blockers = (
    _dependabot_evidence._dependabot_exception_payload_blockers
)
github_dependabot_alerts = _dependabot_evidence.github_dependabot_alerts
OptionalOwnerEvidenceSpec = _evidence_common.OptionalOwnerEvidenceSpec
Runner = _evidence_common.Runner
_check = _evidence_common._check
_non_empty_text = _evidence_common._non_empty_text
_normalized_text = _evidence_common._normalized_text
_optional_owner_evidence_coverage = _evidence_common._optional_owner_evidence_coverage
_run_json = _evidence_common._run_json
_run_text = _evidence_common._run_text
GitHubPrLocalStateSnapshot = _github_local_state.GitHubPrLocalStateSnapshot
_github_pr_head_metadata = _github_local_state._github_pr_head_metadata
_github_pr_local_state_blockers = _github_local_state._github_pr_local_state_blockers
_github_pr_local_state_evidence = _github_local_state._github_pr_local_state_evidence
_local_git_dirty_count = _github_local_state._local_git_dirty_count
_local_git_head = _github_local_state._local_git_head
_pr_head_oid = _github_local_state._pr_head_oid
github_pr_local_state = _github_local_state.github_pr_local_state
GitHubPrCheckEvidenceInputs = _github_pr_checks_evidence.GitHubPrCheckEvidenceInputs
_changed_file_top_level_paths = _github_pr_checks_evidence._changed_file_top_level_paths
_github_pr_changed_file_paths = _github_pr_checks_evidence._github_pr_changed_file_paths
_github_pr_check_blockers_with_files = (
    _github_pr_checks_evidence._github_pr_check_blockers_with_files
)
_github_pr_check_evidence = _github_pr_checks_evidence._github_pr_check_evidence
DEFAULT_PRODUCTION_ENVIRONMENT = (
    _github_repository_evidence.DEFAULT_PRODUCTION_ENVIRONMENT
)
DEFAULT_PRODUCTION_REVIEWER = _github_repository_evidence.DEFAULT_PRODUCTION_REVIEWER
_branch_protection_blockers = _github_repository_evidence._branch_protection_blockers
_classic_required_check_contexts = (
    _github_repository_evidence._classic_required_check_contexts
)
_github_rulesets = _github_repository_evidence._github_rulesets
_protection_payload = _github_repository_evidence._protection_payload
github_branch_protection = _github_repository_evidence.github_branch_protection
github_production_environment = (
    _github_repository_evidence.github_production_environment
)
ADVISORY_REVIEW_THREAD_AUTHORS = _github_review_threads.ADVISORY_REVIEW_THREAD_AUTHORS
ReviewThreadPageRequest = _github_review_threads.ReviewThreadPageRequest
_collect_review_thread_nodes = _github_review_threads._collect_review_thread_nodes
_dict_child = _github_review_threads._dict_child
_fetch_review_thread_page = _github_review_threads._fetch_review_thread_page
_next_review_thread_cursor = _github_review_threads._next_review_thread_cursor
_review_thread_blockers = _github_review_threads._review_thread_blockers
_review_thread_blocks = _github_review_threads._review_thread_blocks
_review_thread_counts = _github_review_threads._review_thread_counts
_review_thread_first_comment = _github_review_threads._review_thread_first_comment
_review_thread_is_advisory = _github_review_threads._review_thread_is_advisory
_review_thread_unresolved = _github_review_threads._review_thread_unresolved
_review_threads_command = _github_review_threads._review_threads_command
_review_threads_page = _github_review_threads._review_threads_page
_review_threads_query = _github_review_threads._review_threads_query
_unresolved_review_threads = _github_review_threads._unresolved_review_threads
github_review_threads = _github_review_threads.github_review_threads
ALLOWED_SKIPPED_CHECKS = _github_rollup.ALLOWED_SKIPPED_CHECKS
COVERED_AGGREGATE_ALLOWED_CONCLUSIONS = (
    _github_rollup.COVERED_AGGREGATE_ALLOWED_CONCLUSIONS
)
COVERED_AGGREGATE_CHECKS = _github_rollup.COVERED_AGGREGATE_CHECKS
CURRENT_CHECK_NAME_ENV = _github_rollup.CURRENT_CHECK_NAME_ENV
PASSING_CHECK_CONCLUSIONS = _github_rollup.PASSING_CHECK_CONCLUSIONS
PASSING_STATUS_STATES = _github_rollup.PASSING_STATUS_STATES
_current_check_in_progress_labels = _github_rollup._current_check_in_progress_labels
_current_check_names_from_env = _github_rollup._current_check_names_from_env
_github_pr_check_blockers = _github_rollup._github_pr_check_blockers
_non_passing_rollup_labels = _github_rollup._non_passing_rollup_labels
_rollup_check_run_succeeded = _github_rollup._rollup_check_run_succeeded
_rollup_entry_allowed_covered_aggregate = (
    _github_rollup._rollup_entry_allowed_covered_aggregate
)
_rollup_entry_current_check_in_progress = (
    _github_rollup._rollup_entry_current_check_in_progress
)
_rollup_entry_label = _github_rollup._rollup_entry_label
_rollup_entry_passed = _github_rollup._rollup_entry_passed

SECURITY_ACCOUNT_ATTESTATION_REQUIRED_FIELDS = (
    _security_account_evidence.SECURITY_ACCOUNT_ATTESTATION_REQUIRED_FIELDS
)
SECURITY_ACCOUNT_ATTESTATION_ACCOUNT_FIELDS = (
    _security_account_evidence.SECURITY_ACCOUNT_ATTESTATION_ACCOUNT_FIELDS
)
SECURITY_ACCOUNT_ALLOWED_APPROVALS = (
    _security_account_evidence.SECURITY_ACCOUNT_ALLOWED_APPROVALS
)
SECURITY_ACCOUNT_ALLOWED_HUMAN_ACCESS = (
    _security_account_evidence.SECURITY_ACCOUNT_ALLOWED_HUMAN_ACCESS
)
SECURITY_ACCOUNT_ALLOWED_ACTIVE_KEY = (
    _security_account_evidence.SECURITY_ACCOUNT_ALLOWED_ACTIVE_KEY
)
SECURITY_ACCOUNT_ALLOWED_BOUNDARY = (
    _security_account_evidence.SECURITY_ACCOUNT_ALLOWED_BOUNDARY
)
SECURITY_ACCOUNT_ATTESTED_CONTROLS = (
    _security_account_evidence.SECURITY_ACCOUNT_ATTESTED_CONTROLS
)
_security_account_attestation_coverage = (
    _security_account_evidence._security_account_attestation_coverage
)
_security_account_attestation_payload_blockers = (
    _security_account_evidence._security_account_attestation_payload_blockers
)
_security_account_attestation_choice_blockers = (
    _security_account_evidence._security_account_attestation_choice_blockers
)
_security_account_attestation_expiry_blockers = (
    _security_account_evidence._security_account_attestation_expiry_blockers
)
_security_account_attestation_account_blockers = (
    _security_account_evidence._security_account_attestation_account_blockers
)
_security_account_attestation_summary = (
    _security_account_evidence._security_account_attestation_summary
)
IAM_ACCESS_KEY_STALE_DAYS = _aws_iam_access.IAM_ACCESS_KEY_STALE_DAYS
aws_identity = _aws_iam_access.aws_identity
aws_iam_account_access = _aws_iam_access.aws_iam_account_access
_iam_user_names = _aws_iam_access._iam_user_names
_iam_access_key_counts = _aws_iam_access._iam_access_key_counts
_record_access_key_metadata = _aws_iam_access._record_access_key_metadata
_access_key_metadata_fields = _aws_iam_access._access_key_metadata_fields
_record_active_access_key_age = _aws_iam_access._record_active_access_key_age
_record_active_access_key_last_used = (
    _aws_iam_access._record_active_access_key_last_used
)
_parse_aws_timestamp = _aws_iam_access._parse_aws_timestamp
_iam_account_access_evidence = _aws_iam_access._iam_account_access_evidence
_iam_account_access_blockers = _aws_iam_access._iam_account_access_blockers
_summary_int = _aws_iam_access._summary_int
aws_cost_controls = _aws_cost_evidence.aws_cost_controls
_account_id_from_identity = _aws_cost_evidence._account_id_from_identity
_run_count = _aws_cost_evidence._run_count
ALERT_ROUTE_OBSERVATION_REQUIRED_FIELDS = (
    _alert_route_observation.ALERT_ROUTE_OBSERVATION_REQUIRED_FIELDS
)
ALERT_ROUTE_OBSERVATION_ROUTE_FIELDS = (
    _alert_route_observation.ALERT_ROUTE_OBSERVATION_ROUTE_FIELDS
)
ALERT_ROUTE_OBSERVATION_QUEUE_FIELDS = (
    _alert_route_observation.ALERT_ROUTE_OBSERVATION_QUEUE_FIELDS
)
ALERT_ROUTE_ALLOWED_DECISIONS = _alert_route_observation.ALERT_ROUTE_ALLOWED_DECISIONS
ALERT_ROUTE_OBSERVATION_SPEC = _alert_route_observation.ALERT_ROUTE_OBSERVATION_SPEC
_alert_route_observation_coverage = (
    _alert_route_observation._alert_route_observation_coverage
)
_alert_route_observation_payload_blockers = (
    _alert_route_observation._alert_route_observation_payload_blockers
)
_alert_route_observation_choice_blockers = (
    _alert_route_observation._alert_route_observation_choice_blockers
)
_alert_route_observation_expiry_blockers = (
    _alert_route_observation._alert_route_observation_expiry_blockers
)
_alert_route_observation_route_blockers = (
    _alert_route_observation._alert_route_observation_route_blockers
)
_alert_route_observation_summary = (
    _alert_route_observation._alert_route_observation_summary
)
aws_sns_alert_route = _aws_alert_route.aws_sns_alert_route
_sns_subscription_items = _aws_alert_route._sns_subscription_items
_sqs_subscription_queue_metadata = _aws_alert_route._sqs_subscription_queue_metadata
_queue_name_from_sqs_arn = _aws_alert_route._queue_name_from_sqs_arn
_metadata_int = _aws_metadata._metadata_int
_metadata_dict = _aws_metadata._metadata_dict
_metadata_list = _aws_metadata._metadata_list
_cloudtrail_management_selector_found = (
    _aws_cloudtrail._cloudtrail_management_selector_found
)
_cloudtrail_trail_blockers = _aws_cloudtrail._cloudtrail_trail_blockers
_cloudtrail_status_blockers = _aws_cloudtrail._cloudtrail_status_blockers
_cloudtrail_selector_blockers = _aws_cloudtrail._cloudtrail_selector_blockers
aws_cloudtrail_management_events = _aws_cloudtrail.aws_cloudtrail_management_events
PRODUCTION_DR_OWNER_REQUIRED_FIELDS = (
    _restore_evidence.PRODUCTION_DR_OWNER_REQUIRED_FIELDS
)
PRODUCTION_DR_OWNER_RESTORE_FIELDS = (
    _restore_evidence.PRODUCTION_DR_OWNER_RESTORE_FIELDS
)
PRODUCTION_DR_OWNER_TEXT_FIELDS = _restore_evidence.PRODUCTION_DR_OWNER_TEXT_FIELDS
PRODUCTION_DR_OWNER_ALLOWED_APPROVALS = (
    _restore_evidence.PRODUCTION_DR_OWNER_ALLOWED_APPROVALS
)
PRODUCTION_DR_OWNER_SUMMARY_FIELDS = (
    _restore_evidence.PRODUCTION_DR_OWNER_SUMMARY_FIELDS
)
PRODUCTION_DR_OWNER_SPEC = _restore_evidence.PRODUCTION_DR_OWNER_SPEC
RESTORE_DRILL_REQUIRED_FIELDS = _restore_evidence.RESTORE_DRILL_REQUIRED_FIELDS
aws_restore_jobs = _restore_evidence.aws_restore_jobs
_read_restore_drill_payload = _restore_evidence._read_restore_drill_payload
_restore_drill_payload_blockers = _restore_evidence._restore_drill_payload_blockers
_restore_drill_evidence_payload = _restore_evidence._restore_drill_evidence_payload
restore_drill_evidence = _restore_evidence.restore_drill_evidence
_production_dr_owner_coverage = _restore_evidence._production_dr_owner_coverage
_production_dr_owner_payload_blockers = (
    _restore_evidence._production_dr_owner_payload_blockers
)
_production_dr_owner_expiry_blockers = (
    _restore_evidence._production_dr_owner_expiry_blockers
)
_production_dr_owner_restore_blockers = (
    _restore_evidence._production_dr_owner_restore_blockers
)
_production_dr_owner_summary = _restore_evidence._production_dr_owner_summary
catalog_fanout_report = _repository_fanout_evidence.catalog_fanout_report
_evidence_repository_catalog_paths = (
    _repository_fanout_evidence._evidence_repository_catalog_paths
)
EXAMPLE_CATALOG_NAMES = _repository_fanout_evidence.EXAMPLE_CATALOG_NAMES
ENV_STRING_DEFAULTS = {
    "aws_account_id": "AWS_ACCOUNT_ID",
    "operations_topic_arn": "OPERATIONS_TOPIC_ARN",
    "operations_cloudtrail_name": "OPERATIONS_CLOUDTRAIL_NAME",
}
ENV_PATH_DEFAULTS = {
    "dependabot_exception_evidence": "DEPENDABOT_EXCEPTION_EVIDENCE",
    "security_account_attestation_evidence": "SECURITY_ACCOUNT_ATTESTATION_EVIDENCE",
    "alert_route_observation_evidence": "ALERT_ROUTE_OBSERVATION_EVIDENCE",
    "production_dr_owner_evidence": "PRODUCTION_DR_OWNER_EVIDENCE",
    "restore_drill_evidence": "RESTORE_DRILL_EVIDENCE",
    "question_matrix_evidence": "QUESTION_MATRIX_EVIDENCE",
    "external_control_evidence": "EXTERNAL_CONTROL_EVIDENCE",
}
READINESS_GATES = _scoring.READINESS_GATES
AWS_WELL_ARCHITECTED_TOC_URL = _structured_evidence.AWS_WELL_ARCHITECTED_TOC_URL
STRUCTURED_EVIDENCE_ALLOWED_STATUSES = (
    _structured_evidence.STRUCTURED_EVIDENCE_ALLOWED_STATUSES
)
QUESTION_MATRIX_REQUIRED_FIELDS = _structured_evidence.QUESTION_MATRIX_REQUIRED_FIELDS
EXTERNAL_CONTROL_REQUIRED_FIELDS = _structured_evidence.EXTERNAL_CONTROL_REQUIRED_FIELDS
REQUIRED_EXTERNAL_CONTROL_IDS = _structured_evidence.REQUIRED_EXTERNAL_CONTROL_IDS
MISSING_QUESTION_ID = _structured_evidence.MISSING_QUESTION_ID
EXPECTED_WELL_ARCHITECTED_QUESTION_PREFIX_PILLARS = (
    _structured_evidence.EXPECTED_WELL_ARCHITECTED_QUESTION_PREFIX_PILLARS
)
EXPECTED_WELL_ARCHITECTED_QUESTION_PREFIX_COUNTS = (
    _structured_evidence.EXPECTED_WELL_ARCHITECTED_QUESTION_PREFIX_COUNTS
)
EXPECTED_WELL_ARCHITECTED_QUESTION_IDS = (
    _structured_evidence.EXPECTED_WELL_ARCHITECTED_QUESTION_IDS
)
EXPECTED_WELL_ARCHITECTED_QUESTION_PILLAR_BY_ID = (
    _structured_evidence.EXPECTED_WELL_ARCHITECTED_QUESTION_PILLAR_BY_ID
)
EXPECTED_WELL_ARCHITECTED_QUESTION_COUNT = (
    _structured_evidence.EXPECTED_WELL_ARCHITECTED_QUESTION_COUNT
)
EXPECTED_WELL_ARCHITECTED_QUESTION_COUNTS = (
    _structured_evidence.EXPECTED_WELL_ARCHITECTED_QUESTION_COUNTS
)
STRUCTURED_EVIDENCE_MAX_AGE_DAYS = _structured_evidence.STRUCTURED_EVIDENCE_MAX_AGE_DAYS
StructuredEvidenceSpec = _structured_evidence.StructuredEvidenceSpec
question_matrix_evidence = _structured_evidence.question_matrix_evidence
external_control_evidence = _structured_evidence.external_control_evidence
_structured_evidence_check = _structured_evidence._structured_evidence_check
_read_required_structured_evidence = (
    _structured_evidence._read_required_structured_evidence
)
_read_structured_evidence_payload = (
    _structured_evidence._read_structured_evidence_payload
)
_structured_evidence_payload_blockers = (
    _structured_evidence._structured_evidence_payload_blockers
)
_structured_evidence_field_present = (
    _structured_evidence._structured_evidence_field_present
)
_structured_evidence_mismatch_blockers = (
    _structured_evidence._structured_evidence_mismatch_blockers
)
_structured_evidence_freshness_blockers = (
    _structured_evidence._structured_evidence_freshness_blockers
)
_parse_reviewed_at = _structured_evidence._parse_reviewed_at
_structured_evidence_count_blockers = (
    _structured_evidence._structured_evidence_count_blockers
)
_structured_evidence_control_blockers = (
    _structured_evidence._structured_evidence_control_blockers
)
_question_matrix_source_verification_blockers = (
    _structured_evidence._question_matrix_source_verification_blockers
)
_question_matrix_score_blockers = _structured_evidence._question_matrix_score_blockers
_question_matrix_score_id_blockers = (
    _structured_evidence._question_matrix_score_id_blockers
)
_question_matrix_observed_ids = _structured_evidence._question_matrix_observed_ids
_question_matrix_pillar_blockers = _structured_evidence._question_matrix_pillar_blockers
_expected_question_id_order = _structured_evidence._expected_question_id_order
_sort_question_ids = _structured_evidence._sort_question_ids
_question_id_sort_key = _structured_evidence._question_id_sort_key
_question_matrix_score_count_blockers = (
    _structured_evidence._question_matrix_score_count_blockers
)
_question_matrix_invalid_score_blockers = (
    _structured_evidence._question_matrix_invalid_score_blockers
)
_invalid_question_score = _structured_evidence._invalid_question_score
_question_matrix_status_blockers = _structured_evidence._question_matrix_status_blockers
_question_matrix_score_status_blockers = (
    _structured_evidence._question_matrix_score_status_blockers
)
_valid_question_score = _structured_evidence._valid_question_score
_question_matrix_evidence_ref_blockers = (
    _structured_evidence._question_matrix_evidence_ref_blockers
)
_question_matrix_summary_blockers = (
    _structured_evidence._question_matrix_summary_blockers
)
_question_matrix_unresolved_id_blockers = (
    _structured_evidence._question_matrix_unresolved_id_blockers
)
_question_matrix_pillar_unresolved_blockers = (
    _structured_evidence._question_matrix_pillar_unresolved_blockers
)
_question_matrix_average_blockers = (
    _structured_evidence._question_matrix_average_blockers
)
_non_passed_question_ids = _structured_evidence._non_passed_question_ids
_expected_pillar_unresolved_question_counts = (
    _structured_evidence._expected_pillar_unresolved_question_counts
)
_expected_pillar_question_score_averages = (
    _structured_evidence._expected_pillar_question_score_averages
)
_rounded_average = _structured_evidence._rounded_average
_question_id_list_text = _structured_evidence._question_id_list_text
_missing_external_control_blockers = (
    _structured_evidence._missing_external_control_blockers
)
_external_control_id_blockers = _structured_evidence._external_control_id_blockers
_external_control_status_blockers = (
    _structured_evidence._external_control_status_blockers
)
_external_control_count_blockers = _structured_evidence._external_control_count_blockers
_external_control_unresolved_count_blockers = (
    _structured_evidence._external_control_unresolved_count_blockers
)
_external_control_unresolved_id_blockers = (
    _structured_evidence._external_control_unresolved_id_blockers
)
_valid_structured_status = _structured_evidence._valid_structured_status
_allowed_status_text = _structured_evidence._allowed_status_text
_external_control_proof_blockers = _structured_evidence._external_control_proof_blockers
_non_empty_string_list = _structured_evidence._non_empty_string_list
_structured_evidence_payload = _structured_evidence._structured_evidence_payload
_control_ids = _structured_evidence._control_ids
_question_matrix_payload_fields = _structured_evidence._question_matrix_payload_fields
_question_score_scale = _structured_evidence._question_score_scale
_external_control_payload_fields = _structured_evidence._external_control_payload_fields
_unresolved_question_evidence_ref_ids = (
    _structured_evidence._unresolved_question_evidence_ref_ids
)
_framework_source_verification_summary = (
    _structured_evidence._framework_source_verification_summary
)
_string_list = _structured_evidence._string_list
_string_key_number_map = _structured_evidence._string_key_number_map
_string_key_int_map = _structured_evidence._string_key_int_map
_unresolved_control_ids = _structured_evidence._unresolved_control_ids
_unresolved_control_ids_from_controls = (
    _structured_evidence._unresolved_control_ids_from_controls
)


def repository_fanout_evidence(
    root_dir: Path, args: argparse.Namespace
) -> dict[str, object]:
    """Delegate fanout evidence while preserving collector-level monkeypatch hooks."""
    previous_catalog_report = _repository_fanout_evidence.catalog_fanout_report
    previous_catalog_paths = (
        _repository_fanout_evidence._evidence_repository_catalog_paths
    )
    _repository_fanout_evidence.catalog_fanout_report = catalog_fanout_report
    _repository_fanout_evidence._evidence_repository_catalog_paths = (
        _evidence_repository_catalog_paths
    )
    try:
        return _repository_fanout_evidence.repository_fanout_evidence(root_dir, args)
    finally:
        _repository_fanout_evidence.catalog_fanout_report = previous_catalog_report
        _repository_fanout_evidence._evidence_repository_catalog_paths = (
            previous_catalog_paths
        )


PILLAR_CHECKS = _scoring.PILLAR_CHECKS
WELL_ARCHITECTED_SCORE_CAP = _scoring.WELL_ARCHITECTED_SCORE_CAP
pillar_scores = _scoring.pillar_scores
well_architected_scores = _scoring.well_architected_scores
score_blockers = _scoring.score_blockers


def github_pr_checks(
    repo: str, pr_number: int | None, *, runner: Runner = run
) -> dict[str, object]:
    """Preserve every PR gate and verify the central promotion independently."""
    result = _github_pr_checks_evidence.github_pr_checks(repo, pr_number, runner=runner)
    if repo == _repository_controls.CENTRAL_REPOSITORY and pr_number is not None:
        return _github_repository_evidence.with_current_promotion(result, pr_number)
    return result


def collect_evidence(
    args: argparse.Namespace, *, runner: Runner = run
) -> dict[str, Any]:
    """Collect metadata-only Well-Architected evidence."""
    checks = [
        *github_pr_context_evidence(args, runner=runner),
        github_branch_protection(
            args.repo,
            args.branch,
            expected_required_status_checks=(
                args.required_status_check
                or _repository_controls.required_status_checks_for_repository(args.repo)
            ),
            runner=runner,
        ),
        github_dependabot_alerts(
            DependabotAlertRequest(
                repo=args.repo,
                dependency=args.dependabot_dependency,
                manifest_path=args.dependabot_manifest,
            ),
            exception_evidence=args.dependabot_exception_evidence,
            runner=runner,
        ),
        github_production_environment(
            args.repo,
            args.production_environment,
            args.production_reviewer,
            runner=runner,
        ),
        aws_identity(runner=runner),
        aws_iam_account_access(
            attestation_evidence=args.security_account_attestation_evidence,
            runner=runner,
        ),
        aws_cost_controls(args.aws_account_id, runner=runner),
        aws_sns_alert_route(
            args.operations_topic_arn,
            observation_evidence=args.alert_route_observation_evidence,
            runner=runner,
        ),
        aws_cloudtrail_management_events(
            args.operations_cloudtrail_name, runner=runner
        ),
        aws_restore_jobs(args.restore_window_days, runner=runner),
        restore_drill_evidence(
            args.restore_drill_evidence,
            production_dr_owner_evidence=args.production_dr_owner_evidence,
        ),
        repository_fanout_evidence(args.root_dir, args),
        question_matrix_evidence(args),
        external_control_evidence(args),
    ]
    proxy_scores = pillar_scores(checks)
    return {
        "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "repo": args.repo,
        "pr": args.pr,
        "branch": args.branch,
        "checks": checks,
        "proxyPillarScores": proxy_scores,
        "pillarScores": well_architected_scores(proxy_scores, checks),
        "scoreBlockers": score_blockers(checks),
        "blockers": [*_all_blockers(checks), *score_blockers(checks)],
    }


def github_pr_context_evidence(
    args: argparse.Namespace, *, runner: Runner = run
) -> list[dict[str, object]]:
    """Return PR evidence when available, or mark PR-only gates not applicable."""
    if args.pr is not None:
        return [
            github_pr_checks(args.repo, args.pr, runner=runner),
            github_pr_local_state(args.repo, args.pr, args.root_dir, runner=runner),
            github_review_threads(args.repo, args.pr, runner=runner),
        ]

    return [
        _not_applicable_pr_check(
            "github_pr_checks",
            args.branch,
            "No pull request number is available in this branch evidence context.",
        ),
        _not_applicable_pr_check(
            "github_pr_local_state",
            args.branch,
            "Local PR head comparison only applies to pull request evidence.",
        ),
        _not_applicable_pr_check(
            "github_review_threads",
            args.branch,
            "Review-thread evidence only applies to pull request evidence.",
        ),
    ]


def _not_applicable_pr_check(name: str, branch: str, reason: str) -> dict[str, object]:
    """Return a normalized branch-context result for PR-only evidence checks."""
    return _check(
        name,
        status="not_applicable",
        evidence={
            "branch": branch,
            "reason": reason,
            "scope": "branch",
        },
    )


def render_markdown_report(report: dict[str, Any]) -> str:
    """Render a sanitized Markdown summary for CI artifacts and step summaries."""
    return _markdown.render_markdown_report(
        report, EXPECTED_WELL_ARCHITECTED_QUESTION_COUNTS
    )


def _score_table_rows(value: object) -> list[str]:
    """Return Markdown table rows for a pillar score mapping."""
    return _markdown.score_table_rows(value, EXPECTED_WELL_ARCHITECTED_QUESTION_COUNTS)


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""
    parser = argparse.ArgumentParser(
        description="Collect metadata-only Well-Architected evidence.",
    )
    parser.add_argument("--repo", default="VilnaCRM-Org/bootstrap-infrastructure")
    parser.add_argument("--branch", default="main")
    parser.add_argument("--pr", type=int)
    parser.add_argument("--aws-account-id")
    parser.add_argument("--operations-topic-arn")
    parser.add_argument("--operations-cloudtrail-name")
    parser.add_argument(
        "--production-environment",
        default=DEFAULT_PRODUCTION_ENVIRONMENT,
        help="GitHub environment that must protect production deployments.",
    )
    parser.add_argument(
        "--production-reviewer",
        default=DEFAULT_PRODUCTION_REVIEWER,
        help="GitHub login expected to approve production deployments.",
    )
    parser.add_argument(
        "--dependabot-dependency",
        default=DEFAULT_DEPENDABOT_DEPENDENCY,
        help=(
            "Optional dependency name whose open Dependabot alerts block SEC11; "
            "omit to check the entire manifest."
        ),
    )
    parser.add_argument(
        "--dependabot-manifest",
        default=DEFAULT_DEPENDABOT_MANIFEST,
        help="Manifest path whose open Dependabot alerts block SEC11.",
    )
    parser.add_argument(
        "--dependabot-exception-evidence",
        type=Path,
        help=(
            "Optional non-secret owner-approved exception evidence covering the "
            "current open Dependabot alert numbers."
        ),
    )
    parser.add_argument(
        "--security-account-attestation-evidence",
        type=Path,
        help=(
            "Optional non-secret owner-approved security-account attestation "
            "covering current aggregate IAM account-access evidence."
        ),
    )
    parser.add_argument(
        "--alert-route-observation-evidence",
        type=Path,
        help=(
            "Optional non-secret SRE-approved alert-route observation evidence "
            "covering current stable SNS/SQS route metadata."
        ),
    )
    parser.add_argument(
        "--production-dr-owner-evidence",
        type=Path,
        help=(
            "Optional non-secret production-owner DR evidence covering current "
            "restore-drill metadata, RTO/RPO targets, recovery ownership, "
            "escalation, communications, next review, and retention location."
        ),
    )
    parser.add_argument("--restore-drill-evidence", type=Path)
    parser.add_argument("--question-matrix-evidence", type=Path)
    parser.add_argument("--external-control-evidence", type=Path)
    parser.add_argument("--restore-window-days", type=int, default=90)
    parser.add_argument(
        "--question-matrix-evidence-confirmed",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--external-control-evidence-confirmed",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--required-status-check",
        action="append",
        help=(
            "Exact branch-protection status check context that must be required. "
            "Repeat to override the repository default required-check contract."
        ),
    )
    parser.add_argument("--root-dir", type=Path, default=ROOT_DIR)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--markdown-output", type=Path)
    parser.add_argument("--max-s3-buckets", type=int, default=200)
    parser.add_argument("--max-kms-keys", type=int, default=100)
    parser.add_argument("--max-iam-roles", type=int, default=300)
    parser.add_argument("--max-backup-selections", type=int, default=500)
    parser.add_argument("--max-ecr-repositories", type=int, default=50)
    parser.add_argument("--max-budgets", type=int, default=20)
    parser.add_argument("--max-sns-subscriptions", type=int, default=50)
    parser.add_argument("--max-sqs-queues", type=int, default=50)
    parser.add_argument("--max-cloudtrail-trails", type=int, default=20)
    parser.add_argument("--max-cost-anomaly-monitors", type=int, default=20)
    parser.add_argument("--max-cost-anomaly-subscriptions", type=int, default=20)
    parser.add_argument("--max-cost-allocation-tags", type=int, default=100)
    parser.add_argument("--max-guardduty-detectors", type=int, default=20)
    parser.add_argument("--max-security-hub-accounts", type=int, default=20)
    parser.add_argument("--max-config-recorders", type=int, default=20)
    parser.add_argument("--max-config-delivery-channels", type=int, default=20)
    return parser


def apply_environment_defaults(args: argparse.Namespace) -> argparse.Namespace:
    """Populate omitted standard evidence flags from environment variables."""
    return _env.apply_environment_defaults(args, ENV_STRING_DEFAULTS, ENV_PATH_DEFAULTS)


def main(argv: Sequence[str] | None = None) -> int:
    """Run evidence collection and optionally persist report artifacts."""
    args = apply_environment_defaults(build_parser().parse_args(argv))
    report = collect_evidence(args)
    payload = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(f"{payload}\n", encoding="utf-8")
    if args.markdown_output:
        args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_output.write_text(
            render_markdown_report(report), encoding="utf-8"
        )
    print(payload)
    return 0 if not report["blockers"] else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

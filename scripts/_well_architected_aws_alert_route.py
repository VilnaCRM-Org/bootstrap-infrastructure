from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from _script_support import run
from _well_architected_alert_route_observation import (
    _alert_route_observation_coverage,
)
from _well_architected_aws_metadata import _metadata_int
from _well_architected_evidence_common import Runner, _check, _run_json


def aws_sns_alert_route(
    topic_arn: str | None,
    *,
    observation_evidence: Path | None = None,
    runner: Runner = run,
) -> dict[str, object]:
    """Collect non-secret SNS alert route evidence for the operations topic."""
    if not topic_arn:
        return _check(
            "aws_sns_alert_route",
            status="missing",
            blockers=["Operations SNS topic ARN is required for route evidence."],
        )
    topic_ok, kms_key_id, topic_error = _run_json(
        [
            "aws",
            "sns",
            "get-topic-attributes",
            "--topic-arn",
            topic_arn,
            "--query",
            "Attributes.KmsMasterKeyId",
            "--output",
            "json",
        ],
        runner=runner,
    )
    subs_ok, protocols, subs_error = _run_json(
        [
            "aws",
            "sns",
            "list-subscriptions-by-topic",
            "--topic-arn",
            topic_arn,
            "--query",
            "Subscriptions[].{Protocol:Protocol,Endpoint:Endpoint}",
            "--output",
            "json",
        ],
        runner=runner,
    )
    subscriptions = _sns_subscription_items(protocols)
    protocol_names = [subscription["protocol"] for subscription in subscriptions]
    blockers = []
    sqs_queue: dict[str, object] | None = None
    if not topic_ok:
        blockers.append(f"Unable to query SNS topic attributes: {topic_error}")
    elif not kms_key_id:
        blockers.append("Operations SNS topic is not encrypted with a KMS key.")
    if not subs_ok:
        blockers.append(f"Unable to query SNS subscriptions: {subs_error}")
    elif "sqs" not in protocol_names:
        blockers.append("Operations SNS topic does not have an SQS subscription.")
    else:
        sqs_queue, sqs_blockers = _sqs_subscription_queue_metadata(
            subscriptions,
            runner=runner,
        )
        blockers.extend(sqs_blockers)
    evidence: dict[str, object] = {
        "topicArn": topic_arn,
        "encrypted": bool(kms_key_id),
        "subscriptionCount": len(protocol_names),
        "subscriptionProtocols": sorted(set(protocol_names)),
    }
    if sqs_queue is not None:
        evidence["sqsQueue"] = sqs_queue
    observation_summary, observation_blockers = _alert_route_observation_coverage(
        observation_evidence,
        evidence,
    )
    if observation_summary:
        evidence["alertRouteObservation"] = observation_summary
    blockers.extend(observation_blockers)
    return _check(
        "aws_sns_alert_route",
        status="passed" if not blockers else "failed",
        evidence=evidence,
        blockers=blockers,
    )


def _sns_subscription_items(payload: object) -> list[dict[str, str]]:
    """Normalize SNS subscription query results."""
    if not isinstance(payload, list):
        return []
    subscriptions: list[dict[str, str]] = []
    for item in payload:
        if isinstance(item, str):
            subscriptions.append({"protocol": item, "endpoint": ""})
            continue
        if not isinstance(item, dict):
            continue
        protocol = item.get("Protocol")
        endpoint = item.get("Endpoint")
        if isinstance(protocol, str) and protocol:
            subscriptions.append(
                {
                    "protocol": protocol,
                    "endpoint": endpoint if isinstance(endpoint, str) else "",
                }
            )
    return subscriptions


def _sqs_subscription_queue_metadata(
    subscriptions: Sequence[dict[str, str]],
    *,
    runner: Runner = run,
) -> tuple[dict[str, object] | None, list[str]]:
    """Collect non-secret queue metadata for the first SQS subscription."""
    endpoint = next(
        (
            subscription["endpoint"]
            for subscription in subscriptions
            if subscription["protocol"] == "sqs" and subscription["endpoint"]
        ),
        "",
    )
    queue_name = _queue_name_from_sqs_arn(endpoint)
    if not queue_name:
        return None, ["Unable to derive SQS queue name from SNS subscription."]

    url_ok, queue_url, url_error = _run_json(
        [
            "aws",
            "sqs",
            "get-queue-url",
            "--queue-name",
            queue_name,
            "--query",
            "QueueUrl",
            "--output",
            "json",
        ],
        runner=runner,
    )
    if not url_ok or not isinstance(queue_url, str) or not queue_url:
        return None, [f"Unable to query SQS queue URL: {url_error}"]

    attributes_ok, attributes, attributes_error = _run_json(
        [
            "aws",
            "sqs",
            "get-queue-attributes",
            "--queue-url",
            queue_url,
            "--attribute-names",
            "ApproximateNumberOfMessages",
            "ApproximateNumberOfMessagesNotVisible",
            "ApproximateNumberOfMessagesDelayed",
            "MessageRetentionPeriod",
            "VisibilityTimeout",
            "--query",
            "Attributes",
            "--output",
            "json",
        ],
        runner=runner,
    )
    if not attributes_ok or not isinstance(attributes, dict):
        return None, [f"Unable to query SQS queue attributes: {attributes_error}"]

    return {
        "queueArn": endpoint,
        "queueName": queue_name,
        "visibleMessages": _metadata_int(attributes.get("ApproximateNumberOfMessages")),
        "notVisibleMessages": _metadata_int(
            attributes.get("ApproximateNumberOfMessagesNotVisible")
        ),
        "delayedMessages": _metadata_int(
            attributes.get("ApproximateNumberOfMessagesDelayed")
        ),
        "messageRetentionSeconds": _metadata_int(
            attributes.get("MessageRetentionPeriod")
        ),
        "visibilityTimeoutSeconds": _metadata_int(attributes.get("VisibilityTimeout")),
    }, []


def _queue_name_from_sqs_arn(value: str) -> str:
    """Return the queue name component from an SQS ARN."""
    parts = value.split(":", maxsplit=5)
    if len(parts) != 6 or parts[2] != "sqs" or not parts[5]:
        return ""
    return parts[5]

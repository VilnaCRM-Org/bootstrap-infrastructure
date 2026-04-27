"""Cost management controls for bootstrap infrastructure accounts."""

from __future__ import annotations

from collections.abc import Sequence

import pulumi_aws as aws

import pulumi

from .bootstrap_settings import BootstrapSettings
from .config import settings as default_settings
from .utils.tags import base_tags

COST_ALLOCATION_TAG_KEYS = (
    "App",
    "CostCenter",
    "Criticality",
    "DataClassification",
    "Environment",
    "Owner",
    "RepositoryProject",
    "RetentionClass",
)


def _environment_part(settings: BootstrapSettings) -> str:
    """Return a cost-control-safe environment segment."""
    return settings.sanitize_bucket_component(settings.environment, "environment")


def _budget_name(settings: BootstrapSettings) -> str:
    """Return the deterministic monthly budget name."""
    return f"bootstrap-{_environment_part(settings)}-monthly-cost"


def _anomaly_monitor_name(settings: BootstrapSettings) -> str:
    """Return the deterministic anomaly monitor name."""
    return f"bootstrap-{_environment_part(settings)}-service-cost"


def _anomaly_subscription_name(settings: BootstrapSettings) -> str:
    """Return the deterministic anomaly subscription name."""
    return f"bootstrap-{_environment_part(settings)}-cost-alerts"


def _budget_notifications(
    topic_arn: pulumi.Input[str],
) -> list[aws.budgets.BudgetNotificationArgs]:
    """Return actual and forecasted budget notifications for the operations topic."""
    return [
        aws.budgets.BudgetNotificationArgs(
            comparison_operator="GREATER_THAN",
            notification_type="ACTUAL",
            threshold=80.0,
            threshold_type="PERCENTAGE",
            subscriber_sns_topic_arns=[topic_arn],
        ),
        aws.budgets.BudgetNotificationArgs(
            comparison_operator="GREATER_THAN",
            notification_type="FORECASTED",
            threshold=100.0,
            threshold_type="PERCENTAGE",
            subscriber_sns_topic_arns=[topic_arn],
        ),
    ]


class CostControls(pulumi.ComponentResource):
    """Provision account cost guardrails tied to bootstrap ownership tags."""

    def __init__(
        self,
        name: str,
        *,
        operations_topic_arn: pulumi.Input[str],
        notification_dependencies: Sequence[pulumi.Resource] | None = None,
        settings: BootstrapSettings | None = None,
        opts: pulumi.ResourceOptions | None = None,
    ) -> None:
        """Initialize AWS Budgets and Cost Anomaly Detection controls."""
        super().__init__("bootstrap:cost:CostControls", name, None, opts)

        configured_settings = settings or default_settings
        account_id = aws.get_caller_identity().account_id
        base_opts = pulumi.ResourceOptions(parent=self)
        notification_opts = pulumi.ResourceOptions(
            parent=self,
            depends_on=list(notification_dependencies or []),
        )

        self.cost_allocation_tags: dict[str, aws.costexplorer.CostAllocationTag] = {}
        if configured_settings.manage_cost_allocation_tags:
            for tag_key in COST_ALLOCATION_TAG_KEYS:
                self.cost_allocation_tags[tag_key] = aws.costexplorer.CostAllocationTag(
                    f"{name}-allocation-tag-{tag_key.lower()}",
                    tag_key=tag_key,
                    status="Active",
                    opts=base_opts,
                )

        self.monthly_budget = aws.budgets.Budget(
            f"{name}-monthly-budget",
            account_id=account_id,
            budget_type="COST",
            limit_amount=configured_settings.monthly_budget_limit_usd,
            limit_unit="USD",
            name=_budget_name(configured_settings),
            notifications=_budget_notifications(operations_topic_arn),
            tags=base_tags(
                {"Purpose": "cost-budget"},
                settings=configured_settings,
            ),
            time_unit="MONTHLY",
            opts=notification_opts,
        )
        self.anomaly_monitor: aws.costexplorer.AnomalyMonitor | None = None
        if configured_settings.cost_anomaly_monitor_arn:
            self.anomaly_monitor_arn = pulumi.Output.from_input(
                configured_settings.cost_anomaly_monitor_arn
            )
        else:
            self.anomaly_monitor = aws.costexplorer.AnomalyMonitor(
                f"{name}-anomaly-monitor",
                monitor_dimension="SERVICE",
                monitor_type="DIMENSIONAL",
                name=_anomaly_monitor_name(configured_settings),
                tags=base_tags(
                    {"Purpose": "cost-anomaly-monitor"},
                    settings=configured_settings,
                ),
                opts=base_opts,
            )
            self.anomaly_monitor_arn = self.anomaly_monitor.arn

        self.anomaly_subscription = aws.costexplorer.AnomalySubscription(
            f"{name}-anomaly-subscription",
            account_id=account_id,
            frequency="IMMEDIATE",
            monitor_arn_lists=[self.anomaly_monitor_arn],
            name=_anomaly_subscription_name(configured_settings),
            subscribers=[
                aws.costexplorer.AnomalySubscriptionSubscriberArgs(
                    address=operations_topic_arn,
                    type="SNS",
                )
            ],
            threshold_expression=aws.costexplorer.AnomalySubscriptionThresholdExpressionArgs(
                dimension=aws.costexplorer.AnomalySubscriptionThresholdExpressionDimensionArgs(
                    key="ANOMALY_TOTAL_IMPACT_ABSOLUTE",
                    match_options=["GREATER_THAN_OR_EQUAL"],
                    values=[configured_settings.cost_anomaly_threshold_usd],
                )
            ),
            tags=base_tags(
                {"Purpose": "cost-anomaly-subscription"},
                settings=configured_settings,
            ),
            opts=notification_opts,
        )

        self.register_outputs(
            {
                "monthly_budget_name": self.monthly_budget.name,
                "anomaly_monitor_arn": self.anomaly_monitor_arn,
                "anomaly_subscription_arn": self.anomaly_subscription.arn,
                "cost_allocation_tag_keys": list(self.cost_allocation_tags),
            }
        )


def managed_cost_allocation_tag_keys(
    tags: Sequence[str] = COST_ALLOCATION_TAG_KEYS,
) -> list[str]:
    """Return stable tag keys used by cost allocation controls."""
    return list(tags)

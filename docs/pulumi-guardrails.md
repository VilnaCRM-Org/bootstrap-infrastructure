# Pulumi Guardrails

This repository enforces guardrails in two layers so invalid infrastructure
changes fail early and consistently.

## Runtime guardrails

The Pulumi application layer validates stack metadata before it becomes a
Pulumi `Output`.

- `environment` must be a lowercase slug made of letters, digits, and hyphens.
- `serviceName` must follow the same rule.
- Empty values and surrounding whitespace are rejected.

Those checks live in `pulumi/app/guardrails.py` and are applied by
`EnvironmentSettings` before stack exports and default tags are derived.
The exported `defaultTags` helper includes the mandatory `Project`,
`Environment`, `Owner`, and `CostCenter` tags, using the resolved
service/environment metadata plus the template defaults of `platform` and
`engineering` unless the stack overrides `owner` or `costCenter` in Pulumi
config.

## Policy pack

The `policy/` directory contains the custom VilnaCRM Pulumi CrossGuard pack for
AWS resources. It enforces the repository-specific infrastructure rules that are
most likely to catch risky AI-generated changes:

- tagged AWS resources must include non-empty `Project`, `Environment`, `Owner`,
  and `CostCenter` tags
- AWS regions must stay inside the repository allowlist
- S3 buckets must not become public through ACLs or bucket policies unless they
  are explicitly allowlisted
- critical storage resources must enable encryption at rest
- supported S3 buckets and load balancers must enable access logging
- IAM policies must not use wildcard permissions unless a narrow allowlist and
  justification tag are present
- production-like RDS resources must enable deletion protection, keep final
  snapshots, and avoid public accessibility
- security groups must not expose SSH or RDP to `0.0.0.0/0` or `::/0`,
  including modern ingress-rule resources that use `cidrIpv4` or `cidrIpv6`

The policy-pack source is split so the reusable validation logic is easy to
test:

- `policy/config.py` loads the committed VilnaCRM settings from
  `policy/vilnacrm_guardrails.yaml`
- `policy/guardrails.py` contains pure validation helpers
- `policy/pack.py` defines the Pulumi policy validators and policy list
- `policy/__main__.py` registers the `PolicyPack`
- `policy/PulumiPolicy.yaml` points Pulumi at a repo-local `policy/.venv`
  path so the policy runtime stays portable across CI, Docker, and local shells
- `scripts/prepare_policy_pack.py` keeps the shared `uv` environment ready for
  Pulumi's Python policy runtime and refreshes `policy/.venv` as a symlink to
  the shared interpreter

## Local validation

Use the focused suite when you are editing guardrail logic:

```bash
make test-policy
```

That command enforces 100% line coverage for the Python policy-pack code.
`make test-unit` and `make test-integration` keep the Pulumi application layer
under the same 100% line-coverage contract, so both runtime guardrails and
policy guardrails fail fast when tests drift.

The PR preview workflow also runs the same policy pack during `make test-preview`
before the destructive diff and IAM validation steps inspect the resulting
preview artifact.

`make pulumi-preview` and `make pulumi-up` also enable the policy pack by
default. Before Pulumi starts, the repository checks that the shared
container-managed `uv` environment contains both `pulumi` and
`pulumi-policy`; if the branch changed Python dependencies, the helper resyncs
the environment from `uv.lock` and repoints `policy/.venv` at that shared
interpreter.

For the full non-mutation PR battery:

```bash
make ci-pr
```

For the full local superset, including mutation:

```bash
make ci
```

## CI mapping

GitHub Actions runs `make test-policy` in `pulumi-policy.yml` and also exercises
the policy suite through `make ci-pr` in the local-battery workflow. This keeps
the focused policy check and the aggregate PR battery aligned.

The integration suite also runs a real `pulumi preview --policy-pack ...`
against a local backend, so policy startup failures and public-ACL violations
are caught before merge.

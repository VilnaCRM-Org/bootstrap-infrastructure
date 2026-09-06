# Installation architecture and impact

The trust graph is comment intake → immutable request artifact → trusted runner preflight → fixed account/scope/environment → configuration reader → bounded preview or protected saved-plan apply → drift evidence → protected App publisher. The PR program is a separate input, not an authority for its own permission or successful deployment.

`pulumi_pr_comment.py`, `pulumi_command_preflight.py` and `governance_paths.py` define intake/current-state/routing relationships. The runner workflows consume them from trusted code. `governance_promotion.py` combines real run/artifact/current-PR evidence and the environment/repository control helpers before publishing. The composite configuration action resolves `validate_ci_environment.py` relative to its own reviewed action directory.

`run_pulumi_command.py` → `_pulumi_command_support.py` → `_pulumi_stack_config.py` binds shared provider/configuration identity to the saved plan. The platform entrypoint → neutral account guard → reference-only control constructors preserves the migration boundary. Platform IAM documents, reviewed policy pins and the policy pack must change together when their authorization semantics change.

`Makefile`, Docker/Compose, `pyproject.toml`, `uv.lock` and policy preparation define the reproducible local/hosted test/runtime closure. Structural tests must validate executable references and permissions, while behavioral tests validate API failure/race and identity predicates; neither is a substitute for the other.

The reviewer must inspect runtime paths, architecture boundaries, state/configuration, schemas/events, async workflows, dependencies, tests, documentation, operational visibility, supply chain and security/backward compatibility. No new application database/public API is shipped, but request/evidence artifact schemas and IAM/state interfaces are public contracts for the controller. Treat them as compatibility surfaces.

The existing alert consumer remains the main-version implementation in this installation. Only its configuration credential cutover is shipped. The later typed warning classifier, governance resource construction and service scaffold retain their full follow-up review obligations.

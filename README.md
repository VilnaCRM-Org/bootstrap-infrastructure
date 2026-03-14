[![SWUbanner](https://raw.githubusercontent.com/vshymanskyy/StandWithUkraine/main/banner2-direct.svg)](https://supportukrainenow.org/)

# Infrastructure template for modern DevOps applications

## Possibilities
- Pulumi-based AWS infrastructure for per-repo state, logging, and IAM
- Built-in Docker environment and convenient `make` CLI commands
- CI checks for Pulumi unit, integration, structural, and mutation testing
- Static quality, DevSecOps, and cost guardrail checks for Pulumi/Python code
- Configured testing tools
- Much more!

## Why you might need it
Many DevOps engineers need to create new projects from scratch and spend a lot of time.

We decided to simplify this exhausting process and create a public template for modern infrastructures. This template is used for all our microservices in VilnaCRM.

## License
This software is distributed under the [Creative Commons Zero v1.0 Universal](https://creativecommons.org/publicdomain/zero/1.0/deed) license. Please read [LICENSE](https://github.com/VilnaCRM-Org/infrastructure-template/blob/main/LICENSE) for information on the software availability and distribution.

### Minimal installation
You can clone this repository locally or use GitHub's "Use this template" feature.

Install the latest [docker](https://docs.docker.com/engine/install/) and [docker compose](https://docs.docker.com/compose/install/).

Use `make` to see available commands and start the Pulumi container:
```bash
make start
```

Python dependencies and developer tooling are locked with `uv`.
When you change Python dependencies, regenerate the lockfile with:
```bash
uv lock --python 3.11
```
Static quality checks also use Rust-native tooling where it is a good fit:
`ruff` for Python format/lint, `typos` for repository spellchecking, and
`taplo` for TOML validation.

### Pulumi onboarding (per repository)
Each repository gets its own state bucket named `pulumi-<repo>-<env>-state`.
Each managed repository also gets its own customer-managed KMS key alias named `alias/pulumi-<repo>-<env>-secrets`.
Use AWS KMS for all Pulumi secrets. Do not use `PULUMI_CONFIG_PASSPHRASE`.

Recommended environment variables:
```bash
export PULUMI_BACKEND_URL="s3://pulumi-<repo>-<env>-state/state/<stack>"
export PULUMI_SECRETS_PROVIDER="awskms://alias/pulumi-platform-bootstrap-<env>?region=eu-central-1"
```

Before the first deploy, initialize or select the stack with the KMS-backed secrets provider:
```bash
make pulumi-stack-select STACK=test PULUMI_SECRETS_PROVIDER="$PULUMI_SECRETS_PROVIDER"
```

If the stack was created with a Pulumi passphrase in the past, migrate it in place:
```bash
make pulumi-stack-migrate-secrets STACK=test PULUMI_SECRETS_PROVIDER="$PULUMI_SECRETS_PROVIDER"
```

This bootstrap stack provisions the per-repository KMS keys and grants the matching GitHub deploy role access to only its repository key for `kms:Encrypt`, `kms:Decrypt`, `kms:GenerateDataKey`, `kms:DescribeKey`, and `kms:ReEncrypt*`.
Downstream repositories should use the exported `pulumiSecretsProviderUrls` value for their repository instead of creating a second Pulumi secrets key in the application stack.

`bootstrap-infrastructure` itself is the stage-1 foundation stack, so it cannot rely on a KMS key that it creates during its own first deployment.
Use a pre-existing account or platform bootstrap key for this repository, such as `alias/pulumi-platform-bootstrap-<env>`.
If you later want `bootstrap-infrastructure` to use its own per-repo key, migrate it only after the stack has already created that key.

Store non-secret stack configuration in `pulumi/Pulumi.<stack>.yaml` and set actual secrets with `pulumi config set --secret ...`.

Required config values (namespace `bootstrap-infrastructure`):
- `githubOrg`: GitHub organization name (e.g. `VilnaCRM-Org`)
- `repoSlug`: Repository name (e.g. `bootstrap-infrastructure`)
- `environment`: Stack environment (e.g. `test`, `prod`)
- `owner`: Ownership tag (e.g. `platform`)
- `costCenter`: Cost center tag (e.g. `core`)
- `loggingPrefix`: Prefix for central logging buckets

Optional config values:
- `githubBranch`: Branch allowed for OIDC (defaults to repo default branch)
- `managedRepositories`: List of repositories and default branches when managing multiple repos
- `githubOidcProviderArn`: Pre-existing OIDC provider ARN (if you don't want Pulumi to create one)

Example non-secret stack config (file: `pulumi/Pulumi.test.yaml.example`):
```yaml
config:
  aws:region: eu-central-1
  bootstrap-infrastructure:githubOrg: VilnaCRM-Org
  bootstrap-infrastructure:repoSlug: bootstrap-infrastructure
  bootstrap-infrastructure:environment: test
  bootstrap-infrastructure:owner: platform
  bootstrap-infrastructure:costCenter: core
  bootstrap-infrastructure:githubBranch: main
  bootstrap-infrastructure:managedRepositories:
    - name: bootstrap-infrastructure
      defaultBranch: main
  bootstrap-infrastructure:githubOidcProviderArn: arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com
```

Backend URL format:
```text
s3://pulumi-<repo>-<env>-state/state/<stack>
```

CI requires setting the `PULUMI_STATE_BUCKET` repository variable to the bucket name that matches the
configured repo/environment naming (for example: `pulumi-bootstrap-infrastructure-test-state`).
CI also requires `PULUMI_TEST_SECRETS_PROVIDER` and `PULUMI_PROD_SECRETS_PROVIDER` repository variables, each containing an `awskms://...` URI for the matching environment.

For repositories bootstrapped by this stack, the expected flow is:
```text
bootstrap-infrastructure stack
  -> creates per-repo Pulumi state bucket
  -> creates per-repo Pulumi secrets KMS key + alias
  -> creates per-repo GitHub OIDC deploy role with S3 + KMS permissions
  -> exports pulumiSecretsProviderUrls[repo]

downstream repository
  -> sets PULUMI_BACKEND_URL to its state bucket
  -> sets PULUMI_SECRETS_PROVIDER to its exported awskms:// URI
  -> runs pulumi stack init/select using those bootstrap outputs
```

### Running Pulumi
Common commands (inside the Docker container via `make`):
```bash
make pulumi-preview
make pulumi-up
make pulumi-refresh
make pulumi-destroy
```

Quality and security guardrails:
```bash
make check-static
make check-security
make test-cost
make ci
```

Stack bootstrap helpers:
```bash
make pulumi-stack-select STACK=test PULUMI_SECRETS_PROVIDER="$PULUMI_SECRETS_PROVIDER"
make pulumi-stack-migrate-secrets STACK=test PULUMI_SECRETS_PROVIDER="$PULUMI_SECRETS_PROVIDER"
```

## Using
You can use `make` to control and work with the project locally.

Execute `make` or `make help` to see the full list of project commands.

## Documentation
Start reading at the [GitHub wiki](https://github.com/VilnaCRM-Org/infrastructure-template/wiki). If you're having trouble, head for [the troubleshooting guide](https://github.com/VilnaCRM-Org/infrastructure-template/wiki/Troubleshooting) as it's frequently updated.

## Tests
[Test status](https://github.com/VilnaCRM-Org/infrastructure-template/actions)

If this isn't passing, is there something you can do to help?

## Security
Please disclose any vulnerabilities found responsibly – report security issues to the maintainers privately.

See [SECURITY](https://github.com/VilnaCRM-Org/infrastructure-template/tree/main/SECURITY.md) and [Security advisories on GitHub](https://github.com/VilnaCRM-Org/infrastructure-template/security).

## Contributing
Please submit bug reports, suggestions, and pull requests to the [GitHub issue tracker](https://github.com/VilnaCRM-Org/infrastructure-template/issues).

We're particularly interested in fixing edge cases, expanding test coverage, and updating translations.

If you found a mistake in the docs, or want to add something, go ahead and amend the wiki – anyone can edit it.

## Sponsorship
Development time and resources for this repository are provided by [VilnaCRM](https://vilnacrm.com/), the free and opensource CRM system.

Donations are very welcome, whether in beer 🍺, T-shirts 👕, or cold, hard cash 💰. Sponsorship through GitHub is a simple and convenient way to say "thank you" to maintainers and contributors – just click the "Sponsor" button [on the project page](https://github.com/VilnaCRM-Org/infrastructure-template). If your company uses this template, consider taking part in the VilnaCRM's enterprise support program.

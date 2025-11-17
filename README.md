# Infrastructure Template for Modern DevOps applications

[![SWUbanner](https://raw.githubusercontent.com/vshymanskyy/StandWithUkraine/main/banner2-direct.svg)](https://supportukrainenow.org/)

[![Pulumi Preview](https://github.com/VilnaCRM-Org/infrastructure-template/actions/workflows/pulumi-preview.yml/badge.svg)](https://github.com/VilnaCRM-Org/infrastructure-template/actions/workflows/pulumi-preview.yml)
[![Pulumi Deploy](https://github.com/VilnaCRM-Org/infrastructure-template/actions/workflows/pulumi-deploy.yml/badge.svg)](https://github.com/VilnaCRM-Org/infrastructure-template/actions/workflows/pulumi-deploy.yml)
[![Super Linter](https://github.com/VilnaCRM-Org/infrastructure-template/actions/workflows/super-linter.yml/badge.svg)](https://github.com/VilnaCRM-Org/infrastructure-template/actions/workflows/super-linter.yml)

Production-ready scaffold for teams that want to ship infrastructure-as-code with Pulumi and Docker from day zero.

## Possibilities

- Pulumi (Python) starter that provisions an AWS EC2 instance and exports connection metadata.
- Reproducible Docker Compose workspace with a Pulumi-ready container and helper `make` tasks.
- CI/CD pipelines for previews and deployments, powered by GitHub Actions and Pulumi Cloud.
- Built-in linting via GitHub Super Linter to keep YAML, Markdown, and workflows healthy.
- Documentation on AWS credential management for secure automation using GitHub OIDC or static secrets.

## Why You Might Need It

Spin up consistent project infrastructure without wiring every component manually. This template gives DevOps teams a single source that:

- Encodes best practices from VilnaCRM’s production stack.
- Works out-of-the-box with AWS and Pulumi.
- Keeps cloud changes reviewable with preview pipelines before production deploys.

## License

This software is distributed under the [Creative Commons Zero v1.0 Universal](https://creativecommons.org/publicdomain/zero/1.0/deed) license. Please read [`LICENSE`](LICENSE) for details.

## Documentation

All project docs live under `docs/` to keep everything version controlled. Start with the handbook and jump directly to common topics:

- [Quick Start](docs/README.md#quick-start)
- [Local Tooling](docs/README.md#local-tooling)
- [Development Environment](docs/README.md#development)
- [PyCharm Autocomplete](docs/pycharm-autocomplete.md)
- [CI/CD and Secrets](docs/README.md#cicd-and-secrets)
- [Testing and Validation](docs/README.md#testing-and-validation)
- [Security](docs/README.md#security)
- [Contributing](docs/README.md#contributing)
- [Sponsorship](docs/README.md#sponsorship)

Community Q&A lives under the [`vilnacrm` tag on Stack Overflow](https://stackoverflow.com/questions/tagged/vilnacrm). For questions or feature requests, open an issue.

<!-- BEGIN_TF_DOCS -->
## Requirements

No requirements.

## Providers

No providers.

## Modules

No modules.

## Resources

No resources.

## Inputs

No inputs.

## Outputs

No outputs.
<!-- END_TF_DOCS -->
# Infrastructure Template

[![SWUbanner](https://raw.githubusercontent.com/vshymanskyy/StandWithUkraine/main/banner2-direct.svg)](https://supportukrainenow.org/)

Infrastructure template for modern DevOps applications

## Possibilities

- Modern stack for services: [Pulumi](https://www.pulumi.com)
- Built-in docker environment and convenient `make` cli command
- CI checks to ensure the highest code quality through linters and infrastructure validation
- Configured testing tools
- Much more!

## Why you might need it

Many DevOps engineers need to create new projects from scratch and spend a lot of time.

We decided to simplify this exhausting process and create a public template for modern infrastructures. This template is used for all our microservices in VilnaCRM.

## License

This software is distributed under the [Creative Commons Zero v1.0 Universal](https://creativecommons.org/publicdomain/zero/1.0/deed) license. Please read [LICENSE](https://github.com/VilnaCRM-Org/infrastructure-template/blob/main/LICENSE) for information on the software availability and distribution.

### Minimal installation

You can clone this repository locally or use Github functionality "Use this template"

Install the latest [docker](https://docs.docker.com/engine/install/) and [docker compose](https://docs.docker.com/compose/install/)

Use `make` command to set up project and automatically install all needed dependencies

> make start

Before starting, ensure you have:

1. Installed [Pulumi CLI](https://www.pulumi.com/docs/install/)
2. Configured your cloud provider credentials

Check [Getting started](https://www.pulumi.com/docs/iac/get-started/aws/review-project/) section to manage your infrastructure

That's it. You should now be ready to use infrastructure template!

## Using

You can use `make` command to easily control and work with project locally.

Execute `make` or `make help` to see the full list of project commands.

The list of the `make` possibilities:

```text
build           Builds the images (PHP, caddy)
down            Stop the docker hub
pulumi          Pulumi enables you to safely and predictably create, change, and improve infrastructure.
sh              Log to the docker container
start           Docker container with terraspace and terraform
up              Start the container for development
```

## Documentation

Start reading at the [GitHub wiki](https://github.com/VilnaCRM-Org/infrastructure-template/wiki). If you're having trouble, head for [the troubleshooting guide](https://github.com/VilnaCRM-Org/infrastructure-template/wiki/Troubleshooting) as it's frequently updated.

If the documentation doesn't cover what you need, search the [many questions on Stack Overflow](http://stackoverflow.com/questions/tagged/vilnacrm), and before you ask a question, [read the troubleshooting guide](https://github.com/VilnaCRM-Org/infrastructure-template/wiki/Troubleshooting).

## Tests

[Test status](https://github.com/VilnaCRM-Org/infrastructure-template/actions)

If this isn't passing, is there something you can do to help?

## Repository Synchronization

This template is automatically synchronized with other repositories in our ecosystem. Whenever changes are made to the template, those changes are propagated to dependent projects, ensuring they stay up to date with the latest improvements and best practices.

The synchronization is powered by the [actions-template-sync](https://github.com/AndreasAugustin/actions-template-sync) GitHub Action, which automates the process of propagating updates from this template to other projects.

### Handling Workflow Permissions Error

When setting up the repository synchronization, you may encounter permission-related issues. Below are two methods to resolve common workflow permissions errors: using a Personal Access Token (PAT) or using a GitHub App.

**Important security considerations:**

- Use the principle of least privilege when granting permissions
- Regularly rotate credentials (PATs and GitHub App keys)
- Monitor synchronization logs for unauthorized access attempts

#### Option 1: Using a Personal Access Token (PAT)

Details on how to configure and use a PAT for repository synchronization can be found in the [TEMPLATE_SYNC_PAT.md](.github/TEMPLATE_SYNC_PAT.md) file inside the `.github` directory.

#### Option 2: Using a GitHub App

For projects that prefer GitHub App authentication, please refer to the [TEMPLATE_SYNC_APP.md](.github/TEMPLATE_SYNC_APP.md) file in the `.github` directory for setup instructions and examples.

## Security

Please disclose any vulnerabilities found responsibly – report security issues to the maintainers privately.

See [SECURITY](https://github.com/VilnaCRM-Org/infrastructure-template/tree/main/SECURITY.md) and [Security advisories on GitHub](https://github.com/VilnaCRM-Org/infrastructure-template/security).

## Contributing

Please submit bug reports, suggestions, and pull requests to the [GitHub issue tracker](https://github.com/VilnaCRM-Org/infrastructure-template/issues).

We're particularly interested in fixing edge cases, expanding test coverage, and updating translations.

If you found a mistake in the docs, or want to add something, go ahead and amend the wiki – anyone can edit it.

## Sponsorship

Development time and resources for this repository are provided by [VilnaCRM](https://vilnacrm.com/),
the free and opensource CRM system.

Donations are very welcome, whether in beer 🍺, T-shirts 👕, or cold, hard cash 💰.
Sponsorship through GitHub is a simple and convenient way to say "thank you" to maintainers
and contributors – just click the "Sponsor" button [on the project page](https://github.com/VilnaCRM-Org/infrastructure-template).
If your company uses this template, consider taking part in the VilnaCRM's enterprise support program.

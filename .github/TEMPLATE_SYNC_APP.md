# Template synchronization with GitHub App

Alternatively, you can configure a GitHub App to handle workflow permissions. This method offers a more integrated and secure approach compared to using a Personal Access Token (PAT).

For a detailed guide on how to set up a GitHub App and configure the necessary permissions, refer to the **[GitHub Apps documentation](https://docs.github.com/en/apps/creating-github-apps/creating-github-apps/creating-a-github-app)**.

## Overview

By configuring a GitHub App, you can automate repository synchronization while ensuring secure handling of repository permissions without manual token management.

### Steps Overview

1. **GitHub App Configuration**:

   - Create and configure the GitHub App with the following specific permissions:
     - Repository Administration: Read & Write (for managing repository settings)
     - Repository Contents: Read & Write (for creating PRs and commits)
     - Issues: Read & Write (for creating linked issues if needed)
     - Metadata: Read-only (minimum required permission)
     - Pull Requests: Read & Write (for creating and managing sync PRs)

2. **Repository Secrets**:

   - Configure secrets for the private key and App ID.

3. **Branch Protection Rules**:

   - Navigate to repository Settings > Branches > Branch protection rules
   - Add the GitHub App to the list of accounts allowed to bypass branch protections
   - Ensure "Allow force pushes" is enabled for the GitHub App

4. **Workflow Permissions**:
   - Go to your project's **Settings** > **Actions** > **General**
   - Under the **Workflow permissions** section, check the box for **Allow GitHub Actions to create and approve pull requests**
     > **Security Note**: Enabling this permission allows any workflow in the repository to create and approve pull requests. Ensure all workflows are properly secured and reviewed before enabling this setting.

### GitHub Action Configuration

Below is an example of a GitHub action using the GitHub App for repository synchronization:

```yaml
# File: .github/workflows/template-sync-app.yml
name: Template Sync

on:
  schedule:
    - cron: "0 9 * * MON"
  workflow_dispatch:

permissions:
  contents: write
  pull-requests: write

jobs:
  repo-sync:
    runs-on: ubuntu-latest
    # Prevent concurrent syncs
    concurrency:
      group: template-sync
      cancel-in-progress: true

    steps:
      - name: Generate token to read from source repo
        id: generate_token
        uses: tibdex/github-app-token@v2
        with:
          app_id: ${{ secrets.TEMPLATE_SYNC_APP_ID }}
          private_key: ${{ secrets.TEMPLATE_SYNC_PRIVATE_KEY }}

      - name: Checkout
        uses: actions/checkout@v4
        with:
          token: ${{ steps.generate_token.outputs.token }}
          fetch-depth: 0 # Required for template sync
          # submodules: true  # Uncomment if your repository uses git submodules

      - name: actions-template-sync
        uses: AndreasAugustin/actions-template-sync@v2
        with:
          github_token: ${{ steps.generate_token.outputs.token }}
          source_repo_path: <owner/repo> # e.g., "VilnaCRM-Org/infrastructure-template"
          upstream_branch: <target_branch> # defaults to main, e.g., "master"
          pr_labels: <label1>,<label2>[,...] # optional, e.g., "sync,automated"
          pr_title: "chore: sync with template repository" # optional, customize as needed

      - name: Notify on failure
        if: failure()
        uses: actions/github-script@v7
        with:
          script: |
            github.rest.issues.create({
              owner: context.repo.owner,
              repo: context.repo.repo,
              title: 'Template sync failed',
              body: 'The template sync workflow failed. Please check the workflow logs.'
            })
```

### Security Best Practices

1. **Explicit Permissions**: Define minimal required permissions at the workflow level
2. **Concurrency Control**: Prevent multiple sync jobs from running simultaneously
3. **Full Git History**: Use `fetch-depth: 0` to ensure proper template comparison
4. **Failure Notifications**: Automatically create an issue when sync fails
5. **Descriptive PR Titles**: Use conventional commit format for clarity
6. **Proper Secret Names**: Use descriptive secret names (e.g., `TEMPLATE_SYNC_APP_ID`)
7. **Git Submodules**: If your repository uses git submodules, uncomment `submodules: true` in the checkout step to ensure submodules are synced along with the main repository

## GitHub App vs Personal Access Token (PAT)

While this guide focuses on GitHub Apps (the recommended approach), if you choose to use a Personal Access Token instead, follow these security best practices:

### PAT Security Considerations

1. **Repository Scope Limitation**:

   - Limit the PAT to specific repositories rather than granting access to all repositories
   - Use fine-grained PATs when possible for better security control

2. **Expiration Management**:

   - Set an appropriate expiration date (recommended: 90 days or less)
   - Never create PATs without expiration dates
   - Set up calendar reminders before expiration

3. **Regular Rotation**:

   - Rotate PATs regularly as per security best practices (recommended: every 60-90 days)
   - Update the repository secret immediately after rotation
   - Revoke old PATs after successful rotation

4. **Minimal Permissions**:

   - Grant only the minimum required scopes (`repo`, `workflow`)
   - Avoid granting admin or org-level permissions unless absolutely necessary

5. **Secure Storage**:
   - Never commit PATs to version control
   - Store PATs only in GitHub Secrets
   - Use separate PATs for different purposes/repositories

### Why GitHub Apps are Recommended

- **Scoped permissions**: GitHub Apps have more granular permission controls
- **No expiration**: Apps don't expire like PATs, reducing maintenance overhead
- **Better audit trail**: App actions are clearly attributed in logs
- **Organization-wide management**: Easier to manage at scale
- **Automatic token refresh**: Tokens are short-lived and refreshed automatically

Following these steps should resolve any permission issues with workflows, allowing smooth synchronization between repositories.

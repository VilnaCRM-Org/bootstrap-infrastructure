# Template synchronization with a Personal Access Token (PAT)

Currently, the `GITHUB_TOKEN` cannot be granted workflow permissions by default. You can grant the workflow permissions using a Personal Access Token (PAT) by following these steps:

1. [Create a PAT](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#creating-a-fine-grained-personal-access-token) with the following repository permissions:

   - `contents:write`
   - `workflows:write`
   - `metadata:read`

   To make the options for repository permissions (such as contents:write, workflows:write, and metadata:read) appear, ensure that the access level is not set to read-only.

2. Copy the generated token and [create a new secret](https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions#creating-secrets-for-a-repository) for your target repository.

3. Configure the checkout action to use the token in secrets, as shown below:

   ```yaml
   # File: .github/workflows/template-sync-app.yml

   on:
     # cronjob trigger
     schedule:
       - cron: "0 0 1 * *"
     # manual trigger
     workflow_dispatch:

   jobs:
     repo-sync:
       runs-on: ubuntu-latest
       # https://docs.github.com/en/actions/using-jobs/assigning-permissions-to-jobs
       permissions:
         contents: write
         pull-requests: write

       steps:
         # To use this repository's private action, you must check out the repository
         - name: Checkout
           uses: actions/checkout@v4
           with:
             # submodules: true
             token: ${{ secrets.<secret_name> }}

         - name: actions-template-sync
           uses: AndreasAugustin/actions-template-sync@v2
           with:
             github_token: ${{ secrets.GITHUB_TOKEN }}
             source_repo_path: <owner/repo>
             upstream_branch: <target_branch> # defaults to main
             pr_labels: <label1>,<label2>[,...] # optional, no default
   ```

4. If you encounter the error `pull request create failed: Actions is not permitted to create or approve pull requests (createPullRequest)`, follow these additional steps:

   - Go to your project’s **Settings** > **Actions** > **General**.
   - Under the **Workflow permissions** section, check the box for **Allow GitHub Actions to create and approve pull requests**.

Following these steps should resolve any permission issues with workflows, allowing smooth synchronization between repositories.

## Security Considerations

1. **Scoped Access**:

   - Create fine-grained PATs and scope them to the specific repositories that require synchronization

2. **Expiration Management**:

   - Set an explicit expiration date for every PAT (recommend 90 days or less) and avoid tokens without expiry

3. **Regular Rotation**:

   - Rotate PATs on a 60–90 day cadence and immediately update any workflows or secrets that depend on the token

4. **Minimal Permissions**:

   - Grant only the scopes needed for template synchronization (for example, `contents:write`, `workflows:write`, `metadata:read`)

5. **Secure Storage**:

   - Store PATs only in repository secrets (for example, `TEMPLATE_SYNC_PAT`) and monitor access to ensure secrets are rotated and unused tokens are revoked promptly

# PR Comment Pulumi Promotion Architecture

## Flow

1. `pulumi-pr-commands.yml` runs on `issue_comment.created`.
2. `scripts/pulumi_pr_comment.py` parses the comment and author association.
3. The intake workflow rejects unauthorized authors and fork pull requests.
4. The intake workflow sends `repository_dispatch` with PR number, head SHA,
   target environment, command, and comment ID.
5. `pulumi-pr-command-runner.yml` revalidates the PR head repository and SHA.
6. The runner saves a test plan with `make pulumi-plan`, then runs destructive
   diff and IAM validation against the uploaded preview artifact.
7. `test up` applies the saved test plan and runs drift detection.
8. Production commands also apply and drift-check test first, then enter
   `prod-preview` for the production plan and guardrails.
9. `prod up` enters the protected `prod` environment and applies only the saved
   production plan with `make pulumi-up-plan`.

## Safety Boundaries

- The issue-comment workflow does not check out PR code.
- AWS credentials exist only in the trusted runner jobs bound to GitHub
  environments.
- Each OIDC job uses the environment role configured for its stage: preview,
  apply, or drift, with apply/drift optionally falling back to the preview role
  when dedicated role variables are not set.
- Production jobs are impossible unless the same workflow run has already
  completed test apply and test post-apply drift successfully for that PR head
  SHA.

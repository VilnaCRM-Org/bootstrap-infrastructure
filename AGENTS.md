# AGENTS

This file documents how to refactor code in response to code review feedback.

## Review-driven refactor workflow
1. **Collect feedback**
   - Use `gh pr view <PR>` and `gh pr checks <PR>` for context.
   - Pull review threads with `gh api graphql` to find unresolved or outdated comments.

2. **Classify comments**
   - **Actionable**: concrete change requests (fix a bug, adjust behavior, update config).
   - **Nitpick/Style**: safe to apply if low risk and within scope.
   - **Out-of-scope**: note for follow-up PR or ask reviewer for direction.

3. **Refactor with minimal scope**
   - Make the smallest change that satisfies the comment.
   - Preserve existing patterns and naming conventions.
   - Avoid extra cleanups not requested by the review.

4. **Validate intent**
   - Run the most relevant tests or linters if feasible.
   - If you cannot run checks, note that in the PR update.

5. **Update the PR**
   - Commit with a concise message tied to the review fixes.
   - Push to the existing PR branch.
   - Re-check `gh pr checks` and ensure CI is green.

6. **Close the loop**
   - Ensure each review thread is resolved or outdated.
   - If a reviewer requested a broader change (e.g., split PR), ask for confirmation before restructuring.

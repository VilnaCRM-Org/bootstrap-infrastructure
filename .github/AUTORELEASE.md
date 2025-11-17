# Autorelease action

## Overview

Auto-release workflows automate the process of creating software releases in response to specific triggers like merging a pull request or pushing to a certain branch. This automation helps streamline the development process, reduce human error, and ensure consistent release practices.

---

## Why You Might Need Auto-Release

Consistency: Automating the release process ensures that every release adheres to predefined standards and procedures, reducing the risk of human error and inconsistency in the release quality.

Efficiency: By automating the changelog generation and release process, teams can save time and focus on development and testing rather than on the operational details of creating a release.

Integration: Auto-release workflows can be integrated with other tools and workflows, such as continuous integration (CI) systems, to ensure that releases are made only when all tests pass, maintaining the quality of the code in the production.

Traceability: Automated releases include detailed logs and changelogs, providing a clear audit trail for changes, which is beneficial for debugging and understanding the project’s history.

Speed: Automation accelerates the process of releasing and deploying software, which is especially crucial in high-paced agile environments where multiple releases might occur in a single day.

---

## Setting Up an Auto-Release Workflow

### Step-by-Step Guide

#### 1) The GitHub App configuration

Let's start by creating and configuring a GitHub App. Go to Settings > Developer Settings > GitHub Apps (Developer Settings is at the bottom of the Settings page). Click on New GitHub App.

Once you are creating a new GitHub app, make sure to configure the following:

1. Complete the necessary details for the application:
   - Set a clear, identifiable name (e.g., "YourOrg-AutoRelease")
   - Provide a detailed description of the app's purpose
2. Uncheck the active webhook (not needed for this use case)
3. Configure Repository Permissions (principle of least privilege):
   - Administration: Read & Write (required for branch protection)
   - Contents: Read & Write (required for releases)
   - Issues: Read & Write (required for release notes)
   - Metadata: Read-only (minimum required)
   - Pull Requests: Read & Write (required for automation)
4. For security:

   - Check "Install Only on this account"
   - Enable "Suspend installations on detected abuse"

After creating the app:

1. Install the app on your repository:

   - Go to the app's settings page
   - Click "Install App"
   - Select the repository where you want to use auto-release

2. Generate and secure the private key:

   - In app settings, click "Generate Private Key"
   - The key will be automatically downloaded
   - **IMPORTANT**: Store this key securely - it cannot be downloaded again
   - If the key is ever compromised, revoke it immediately and generate a new one

3. Locate the App ID:
   - Find it at: Settings > Developer Settings > GitHub Apps > Your App > General
   - The App ID is displayed at the top of the page

#### 2) The GitHub repository configuration

Go to Settings > Secrets and Variables > Actions to create new secrets:

1. Add the private key as `PULUMI_AUTORELEASE_APP_KEY`
2. Add the app ID as `PULUMI_AUTORELEASE_APP_ID`

Note: These secrets will be used in the Pulumi-based deployment workflows.

#### 3) Allow force push

⚠️ **CAUTION**: Force push can overwrite repository history. Configure carefully:

1. Go to Settings > Branches > Branch protection rules
2. For the protected branch (e.g., main):
   - Enable "Allow force pushes"
   - **IMPORTANT**: Restrict force pushes to the GitHub App only
   - Do **NOT** allow force pushes for other users or apps

**NOTE**: Force push is required for the auto-release workflow to update version tags, but should be strictly limited to the GitHub App to prevent accidental history rewrites.

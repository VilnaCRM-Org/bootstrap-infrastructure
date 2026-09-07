# Current Well-Architected technical evidence integration

Actual reviewer: Codex (delegated technical review). Review completed 2026-09-06T20:51:21.682863+00:00. Accountable teams remain platform-maintainers/SRE under the existing monthly review cadence. Main source `5c873f86fa956f6b96a09e2887297905467b8562`; all May/April records remain historical and byte-unchanged. No Kravalg signature, risk acceptance or business/on-call commitment is renewed.

## Review outcome

The existing57-row structured matrix is updated from the completed32-answer technical review, plus four now-completed security/route answers (SEC1,SEC3,OPS8,REL6). It records47passed/10unresolved; this document does not recreate the57-row table. Current structured records supersede old all5claims for enforcement. The later remaining-technical review supersedes stale bypass/environment gaps; full acceptance still requires actual promotion, recovery/DR and the question-specific residuals.

TEST and PROD operator/platform saved-plan apply and refreshed no-change drift all passed against main. The eight exact source/plan/time bindings are retained in `specs/issue-17-well-architected-5-of-5/runtime-closure-evidence-2026-09-06.json`. Local operations are not GitHub PR-comment deployments; required actual identity/protection/promotion evidence is not substituted.

## TEST credential and permission review

Fresh IAM facts are5users,3MFAdevices,rootMFAenabled/rootkeysabsent,0activeuserkeys and1inactivekey. All5users lack console profiles and active direct credentials. Two virtual devices bind root; third summary device unclassified. Thus5>3 is a review heuristic, not evidence of5unprotected interactive users. The existing validator is unchanged and still requires a complete valid security record before suppressing that heuristic. No organization-wide SSO claim is made.

Configured boundaries are verified in their source-defined scope: current operator constructs platform boundaries and attaches the control boundary to apply; reviewed source-bound TEST apply plus refreshed no-change drift passed. PR78 readback verified6governed-role boundaries and2immutable documents; governance runtime hash`a7e9487232674f2138d396573d4abd25bb415bea553d9491b2489aa2268a8174` is byte-identical in that review and main. Read roles and credentialless users are not falsely called boundary-attached. The new decision is `boundary_verified`, not a renewed historical `not_required` exemption. Separate unrelated PROD MCPkey remains outside bootstrap authentication, preserved pending consumer migration.

## Current route and operating review

The parent-approved exact synthetic SNSmessage traversed encrypted SNS/SQS, GitHub OIDC run34058543444 and issue202. Only that message was present. Issue creation/normal acknowledgement succeeded; queue counts stayedzero after the visibility interval; only QAissue202 was closed. Existing severity/fallback rules were reviewed. No upstream AWSsource generation, human paging or response guarantee is claimed. Livev1 remains unchanged; v2inert.

Fresh TEST budget actual5.949USD/forecast29.612USD versus100USD, notifications80/100percent and10USD anomaly subscriber are current;10 allocation tagsactive. Tagged bootstrap transfer1.5739275189meteredGB costs0.0122638443USD. Existing1GB/1USD triggers were reviewed, not weakened: ingress/egress can meter the same transfer, dominant0.613GBFrankfurt-to-Ireland supports existingreplica path. Retain regions/data classes and no expansion; no cost saving or new risk approval invented.

Current quotas and bounded CI/KPI sample support technical decisions. Governance fanout stays separate from deployment fanout; never add installed resources twice. Failure KPIs, failed restore and incomplete promotion remain explicit. Review again within30days or immediately after credential/IAM/route/catalog changes; any changed binding invalidates its corresponding evidence.

## Integration and remaining gates

The patch only adds factual records and this concise review, labels the old matrix prose historical, and selects four new evidence inputs in the workflow. The30day freshness, MFA threshold, all-or-nothing attestation, required decisions, immutable source, protected promotion and derived score gates are unchanged. No relevant repository variable override was present at preparation; recheck before publication.

Original assertions1–6and9–11 close through actual current records. ProductionDRdate/expiry7–8stayopen, as do final score caps12–13. The remaining-technical supplement now records10unresolved questions/twocontrols with substantive failure detail instead of stale blanket5scores. Backup/DR historical inputs stay selected until a valid actual replacement exists. The active PR is untouched; parent reviews this prepared patch before applying it.

The [later remaining-technical review](well-architected-remaining-technical-review-2026-09-06.md) records the completed delegated retention/demand/scenario reviews and exact new blockers. Its structured matrix supersedes earlier counts.

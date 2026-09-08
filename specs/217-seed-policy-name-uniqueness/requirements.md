# Seed managed-policy name uniqueness

TEST's first enrollment failed because eleven pairs of managed policies used the
same basename under different IAM paths. IAM requires account-wide, case-insensitive
name uniqueness. This correction is limited to completing the existing PR217 route,
a prerequisite of the approved user-service PoC plan.

| Requirement | Acceptance evidence |
| --- | --- |
| FR1: Every rendered policy name is account-wide unique, ignoring case and path. | Registry rejection tests and both rendered 55-policy inventories. |
| FR2: Rename only eleven proposed policy ARNs per account. | Exact recorded mapping; inverse mapping reproduces the previous complete catalog. |
| FR3: Preserve all six imported boundary identities, documents and logical IDs. | Catalog comparison and import-template regressions. |
| FR4: Preserve the other 38 proposed policy identities retained in TEST. | Mapping intersection, native retained-resource audit and import-only recovery. |
| FR5: Update every principal boundary/attachment reference and catalog integrity pin. | Full catalog equality after inverse mapping and registry closure tests. |
| NFR1: Do not widen policy permissions or assumption trust. | All 55 policy documents and the statement pool remain unchanged; role identities and trust are unchanged. |
| NFR2: Stay within IAM name, policy-size and attachment limits. | Invalid-name regressions, maximum minified policy sizes and attachment counts. |
| NFR3: Preserve independent ownership and fail closed on incomplete installation. | Writer/workflow holds remain until complete enrollment; no automatic retry, deletion or adoption. |
| NFR4: Verify actual changes before executing recovery or enrollment. | Native exact-identity import/update change sets, final inventory and enrollment verification. |

Local source validation does not establish live acceptance. TEST rollback retained
38 policies; those require exact document/attachment verification and explicit
CloudFormation import before a corrected update. The old PROD proposal must not
be executed. Refresh catalog-bound installation packets and the eight-boundary
checkpoint inventory before continuing. No workload permission expansion, new
controller behavior or destructive-override change belongs in this correction.

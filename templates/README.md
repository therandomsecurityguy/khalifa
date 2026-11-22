# Member-account collection templates

CloudFormation for the role the hub assumes to collect member accounts.

| Template                                                       | Use                                                                                                                                                                          |
| -------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`SecurityGraphCollectorRole.yaml`](SecurityGraphCollectorRole.yaml) | One member account: the least-privilege collection role (or attaches the policy to an existing role), trusting the hub IRSA principal(s) with the runtime ExternalId.          |
| [`SecurityGraphCollectorStackSet.yaml`](SecurityGraphCollectorStackSet.yaml) | Organizations-wide: deploys the role above through a StackSet across the approved root/OU ids, in one Region, from a versioned S3 URL (`MemberRoleTemplateUrl`). |

Key parameters (both templates):

- `TrustedPrincipalArn` — the hub organization-collector IRSA role; `AdditionalTrustedPrincipalArn` optionally adds the incremental-collector role.
- `ExternalId` — `NoEcho`, minimum length 16. It is the value stored in the deployment secret (`<name_prefix>-khalifa/runtime`); it is supplied per deploy and never belongs in files, tickets, or chat.
- `CollectorRoleName` / `CreateCollectorRole` / `ExistingRoleName` — create the role or attach the policy to an existing one.

[`scripts/deploy-collector-role.sh`](../scripts/deploy-collector-role.sh) automates per-profile deploys of the single-account template. The install flow is AGENTS.md §1.6; the operational context is [OPERATIONAL.md](../OPERATIONAL.md).

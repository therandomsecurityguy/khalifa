import type { ComplianceControlStatus, ComplianceEvidence } from './compliance-types';
import { ADMIN_PORT_RANGE_PREDICATE } from './admin-ports';

export interface ComplianceRuleEvaluator {
  controlId: string;
  evaluate: (graphClient: any) => Promise<{
    status: ComplianceControlStatus;
    evidence: ComplianceEvidence[];
    issues: string[];
  }>;
}

// CIS v3.0.0 1.14: access keys are rotated every 90 days or less.
const ACCESS_KEY_MAX_AGE_DAYS = 90;
// CIS v3.0.0 1.12: credentials unused for 45 days or greater are disabled.
// Separate from the rotation age: 1.12 used the 90-day rotation constant.
const CREDENTIAL_UNUSED_DAYS = 45;

function readCount(result: unknown[]): number {
  const count = Number(result[0]);
  if (result.length !== 1 || !Number.isSafeInteger(count) || count < 0) {
    throw new Error('Compliance query returned an invalid count');
  }
  return count;
}

// A count of zero only means "clean" if the data it counted over is actually
// present. NetworkAclEntry vertices appear one collector run after the NACLs
// themselves, and every VPC has at least a default NACL, so NACLs without any
// entries means collection has not caught up — not that nothing is exposed.
// Reporting PASS there would show a green tick for a check that looked at
// nothing.
async function networkAclEntriesMissing(graphClient: any): Promise<boolean> {
  const acls = readCount(await graphClient.executeQuery(`g.V().hasLabel('NetworkAcl').count()`));
  if (acls === 0) return false;
  const entries = readCount(
    await graphClient.executeQuery(`g.V().hasLabel('NetworkAclEntry').count()`)
  );
  return entries === 0;
}

function notEvaluated(
  controlId: string,
  reason: string,
  resourceId = 'network-acls',
  resourceType = 'NetworkAcl'
) {
  return {
    status: 'NOT_EVALUATED' as const,
    evidence: [
      {
        controlId,
        resourceId,
        resourceType,
        status: 'NOT_EVALUATED' as const,
        details: { reason },
        collectedAt: new Date().toISOString(),
        collectedBy: 'compliance-engine',
      },
    ],
    issues: [] as string[],
  };
}

// Account ids back from a values() traversal. Anything that is not a 12-digit
// string is a malformed result, and throwing is safer than silently treating
// it as "no accounts" -- that would turn into NOT_EVALUATED or a false PASS.
function readAccountIds(result: unknown[]): string[] {
  for (const value of result) {
    if (typeof value !== 'string' || !/^\d{12}$/.test(value)) {
      throw new Error('Compliance query returned an invalid account id');
    }
  }
  return [...new Set(result as string[])];
}

// Coverage older than two organization collector runs (every 4 hours) is not
// evidence of the account's current state. The run stops at its deadline, so
// an account can go days uncollected while its last complete coverage vertex
// stays in the graph; judging it on that data is how a fixed misconfiguration
// keeps failing, or a new one keeps passing.
export const COLLECTION_MAX_AGE_MS = 8 * 60 * 60 * 1000;

// Coverage of `service` that SUCCEEDED within COLLECTION_MAX_AGE_MS.
// `complete` alone is not enough: the collector marks a SKIPPED stage complete,
// and the global stages (iam, s3, iam-access-keys, iam-credential-report,
// cross-account-trust) are SKIPPED in every region but an account's first, so
// each run writes fresh SKIPPED coverage for them whether or not the real one
// ran. completed_at is an ISO-8601 UTC string, so string order is time order.
function freshCoverage(service: string): string {
  const cutoff = new Date(Date.now() - COLLECTION_MAX_AGE_MS).toISOString();
  return `g.V().hasLabel('CollectionCoverage').has('service', '${service}').has('status', 'SUCCEEDED').has('completed_at', gte('${cutoff}'))`;
}

// Accounts whose `service` collection stage completed recently: the denominator
// for a per-account control. Security Hub scopes most CIS controls to the
// account (resource type AWS::::Account), so one account's compliance says
// nothing about another's; an account whose stage failed, or was last collected
// too long ago, is neither passed nor failed.
async function accountsWithCompleteStage(graphClient: any, service: string): Promise<string[]> {
  return readAccountIds(
    await graphClient.executeQuery(`${freshCoverage(service)}.values('account_id').dedup()`)
  );
}

// Account/region pairs, as "account|region" keys. Config.1, EC2.7 and the like
// are per account per Region, so a recorder in one Region says nothing about
// another. `query` must end in a traversal whose elements carry account_id and
// the given region property.
async function accountRegionPairs(
  graphClient: any,
  query: string,
  regionProperty: 'region' | 'collection_region'
): Promise<string[]> {
  const rows = await graphClient.executeQuery(
    `${query}.project('a', 'r').by('account_id').by('${regionProperty}').dedup()`
  );
  return [
    ...new Set(
      rows.map((row: any) => {
        const account = row instanceof Map ? row.get('a') : row?.a;
        const region = row instanceof Map ? row.get('r') : row?.r;
        if (
          typeof account !== 'string' ||
          !/^\d{12}$/.test(account) ||
          typeof region !== 'string'
        ) {
          throw new Error('Compliance query returned an invalid account/region pair');
        }
        return `${account}|${region}`;
      })
    ),
  ] as string[];
}

function perAccountRegionResult(
  controlId: string,
  resource: { id: string; type: string },
  assessed: string[],
  compliant: ReadonlySet<string>,
  issue: (failing: number) => string,
  // Kept alongside the per-account result, e.g. how many resources violate.
  extraDetails: Record<string, unknown> = {}
) {
  if (assessed.length === 0) {
    return notEvaluated(
      controlId,
      'No account/region has completed the collection this control reads',
      resource.id,
      resource.type
    );
  }
  const failing = assessed.filter((pair) => !compliant.has(pair)).sort();
  const status: ComplianceControlStatus = failing.length === 0 ? 'PASS' : 'FAIL';
  return {
    status,
    evidence: [
      {
        controlId,
        resourceId: resource.id,
        resourceType: resource.type,
        status,
        details: {
          accountRegionsAssessed: assessed.length,
          accountRegionsFailing: failing.length,
          failingAccountRegions: failing.map((pair) => pair.replace('|', ' ')),
          // The assessed set, not just its size: a pair absent from the failures
          // passed only if it was assessed. CIS reconciliation relies on it.
          assessedAccountRegions: [...assessed].sort().map((pair) => pair.replace('|', ' ')),
          ...extraDetails,
        },
        collectedAt: new Date().toISOString(),
        collectedBy: 'compliance-engine',
      },
    ],
    issues: failing.length > 0 ? [issue(failing.length)] : [],
  };
}

// Accounts covered by a trail matching `qualifying` (a Gremlin step chain on
// CloudTrail vertices). An organization trail is one vertex shared by every
// member's collection, its account_id whichever wrote it last, so a qualifying
// organization trail covers every assessed account; any other trail covers its
// own account only.
async function accountsCoveredByTrail(
  graphClient: any,
  assessed: string[],
  qualifying: string
): Promise<Set<string>> {
  const orgTrails = readCount(
    await graphClient.executeQuery(
      `g.V().hasLabel('CloudTrail').has('is_organization_trail', true)${qualifying}.count()`
    )
  );
  if (orgTrails > 0) return new Set(assessed);
  return new Set(
    readAccountIds(
      await graphClient.executeQuery(
        `g.V().hasLabel('CloudTrail')${qualifying}.values('account_id').dedup()`
      )
    )
  );
}

// FAIL names the assessed accounts not in `compliant`; NOT_EVALUATED when no
// account was assessed at all.
function perAccountResult(
  controlId: string,
  resource: { id: string; type: string },
  assessed: string[],
  compliant: ReadonlySet<string>,
  issue: (failing: number) => string,
  // Kept alongside the per-account result, e.g. how many resources violate.
  extraDetails: Record<string, unknown> = {}
) {
  if (assessed.length === 0) {
    return notEvaluated(
      controlId,
      'No account has completed the collection this control reads',
      resource.id,
      resource.type
    );
  }
  const failing = assessed.filter((id) => !compliant.has(id)).sort();
  const status: ComplianceControlStatus = failing.length === 0 ? 'PASS' : 'FAIL';
  return {
    status,
    evidence: [
      {
        controlId,
        resourceId: resource.id,
        resourceType: resource.type,
        status,
        details: {
          accountsAssessed: assessed.length,
          accountsFailing: failing.length,
          failingAccounts: failing,
          // See assessedAccountRegions above.
          assessedAccounts: [...assessed].sort(),
          ...extraDetails,
        },
        collectedAt: new Date().toISOString(),
        collectedBy: 'compliance-engine',
      },
    ],
    issues: failing.length > 0 ? [issue(failing.length)] : [],
  };
}

// Vertices written by a collector older than the property this control reads
// carry no value for it at all. Until one collection pass has run, "no vertex
// has the property" means the data is not there yet, not that it is false.
async function propertyNotYetCollected(
  graphClient: any,
  label: string,
  property: string
): Promise<boolean> {
  const total = readCount(await graphClient.executeQuery(`g.V().hasLabel('${label}').count()`));
  if (total === 0) return false;
  const withProperty = readCount(
    await graphClient.executeQuery(`g.V().hasLabel('${label}').has('${property}').count()`)
  );
  return withProperty === 0;
}

// Per-account and per-account-region results from a traversal of the violating
// elements. Security Hub scopes these controls to the account or
// resource, so an org-wide count could never be checked against it: an account
// fails if it has any violating element, among accounts whose `stage` completed.
// Elements must carry account_id (and collection_region, for the regional form).
async function perAccountViolations(
  graphClient: any,
  controlId: string,
  resource: { id: string; type: string },
  stage: string,
  violating: string,
  issue: (failing: number, violations: number) => string
) {
  const assessed = await accountsWithCompleteStage(graphClient, stage);
  const failing = new Set(
    readAccountIds(await graphClient.executeQuery(`${violating}.values('account_id').dedup()`))
  );
  const violations = readCount(await graphClient.executeQuery(`${violating}.count()`));
  return perAccountResult(
    controlId,
    resource,
    assessed,
    new Set(assessed.filter((id) => !failing.has(id))),
    (n) => issue(n, violations),
    { violations }
  );
}

async function perAccountRegionViolations(
  graphClient: any,
  controlId: string,
  resource: { id: string; type: string },
  stage: string,
  violating: string,
  issue: (failing: number, violations: number) => string,
  // Elements whose state couldn't be read: their account/region is left
  // unassessed, since it would otherwise pass on missing data, unless something
  // there violates anyway.
  unreadable?: string
) {
  const failing = new Set(await accountRegionPairs(graphClient, violating, 'collection_region'));
  const unknown = new Set(
    unreadable ? await accountRegionPairs(graphClient, unreadable, 'collection_region') : []
  );
  const assessed = (await accountRegionPairs(graphClient, freshCoverage(stage), 'region')).filter(
    (pair) => failing.has(pair) || !unknown.has(pair)
  );
  const violations = readCount(await graphClient.executeQuery(`${violating}.count()`));
  return perAccountRegionResult(
    controlId,
    resource,
    assessed,
    new Set(assessed.filter((pair) => !failing.has(pair))),
    (n) => issue(n, violations),
    unreadable ? { violations, accountRegionsUnreadable: unknown.size } : { violations }
  );
}

// Per account for CloudTrail checks. An organization trail is one vertex shared
// by every member's collection, its account_id whichever wrote it last, so a
// failing organization trail fails every assessed account rather than whichever
// account last wrote it; any other failing trail fails its own account.
// `failingTrail` is a step chain applied to CloudTrail vertices.
// S3 bucket names (3-63 of a-z, 0-9, '.', '-'), validated before they are
// interpolated into a query.
const BUCKET_NAME = /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/;

function readBucketNames(rows: unknown[]): string[] {
  return rows.map((name) => {
    if (typeof name !== 'string' || !BUCKET_NAME.test(name)) {
      throw new Error('Compliance query returned an invalid S3 bucket name');
    }
    return name;
  });
}

const gremlinStrings = (values: string[]) => values.map((v) => `'${v}'`).join(', ');

async function perAccountTrailViolations(
  graphClient: any,
  controlId: string,
  resource: { id: string; type: string },
  failingTrail: string,
  issue: (failing: number, trails: number) => string
) {
  const assessed = await accountsWithCompleteStage(graphClient, 'cloudtrail');
  const orgFailing = readCount(
    await graphClient.executeQuery(
      `g.V().hasLabel('CloudTrail').has('is_organization_trail', true)${failingTrail}.count()`
    )
  );
  const failing = new Set(
    orgFailing > 0
      ? assessed
      : readAccountIds(
          await graphClient.executeQuery(
            `g.V().hasLabel('CloudTrail').not(has('is_organization_trail', true))${failingTrail}.values('account_id').dedup()`
          )
        )
  );
  const trails = readCount(
    await graphClient.executeQuery(`g.V().hasLabel('CloudTrail')${failingTrail}.count()`)
  );
  return perAccountResult(
    controlId,
    resource,
    assessed,
    new Set(assessed.filter((id) => !failing.has(id))),
    (n) => issue(n, trails),
    { violations: trails, organizationTrailFailing: orgFailing > 0 }
  );
}

// CIS 1.17 and 1.22 read attachments of AWS-managed policies. Those edges only
// land once the collector emits AWS-managed IamPolicy vertices. Every account
// has some -- service-linked roles carry AWS-managed policies -- so none at all
// means that collector change has not run yet.
async function awsManagedPoliciesNotYetCollected(graphClient: any): Promise<boolean> {
  return (
    readCount(
      await graphClient.executeQuery(
        `g.V().hasLabel('IamPolicy').has('policy_type', 'aws-managed').count()`
      )
    ) === 0
  );
}

export function complianceCutoffIso(days: number, nowMs: number = Date.now()): string {
  if (!Number.isSafeInteger(days) || days < 1 || days > 3650) {
    throw new Error('Compliance cutoff days must be an integer between 1 and 3650');
  }
  if (!Number.isFinite(nowMs)) throw new Error('Compliance cutoff time must be finite');
  const cutoff = new Date(nowMs - days * 24 * 60 * 60 * 1000);
  if (Number.isNaN(cutoff.getTime())) throw new Error('Compliance cutoff time is out of range');
  return cutoff.toISOString();
}

// The root user's posture (AccountMFAEnabled, AccountAccessKeysPresent) is written
// to the vertex arn:aws:iam::<account>:root. list-accounts creates that same id as
// an AwsAccount first, and an upsert by id never changes a label, so in an
// organization deployment the root posture sits on the AwsAccount vertex. Without
// list-accounts it is an IamUser.
const ROOT_USER_VERTICES = `g.V().hasLabel('IamUser', 'AwsAccount').has('arn', endingWith(':root'))`;

export const complianceRuleEvaluators: ComplianceRuleEvaluator[] = [
  {
    controlId: '1.4',
    // IAM.4, per account. The root vertex's arn is arn:aws:iam::<account>:root
    // exactly; matching 'root' anywhere in the arn also caught users such as
    // user/root-admin.
    evaluate: (graphClient) =>
      perAccountViolations(
        graphClient,
        '1.4',
        { id: 'root-account', type: 'IamUser' },
        'iam-access-keys',
        `${ROOT_USER_VERTICES}.out('HAS_ACCESS_KEY')`,
        (n) => `${n} accounts have a root access key`
      ),
  },
  {
    controlId: '1.5',
    evaluate: async (graphClient) => {
      // IAM.9 is per account: it fails an account whose root has no MFA. The
      // previous check passed if any vertex whose arn contained 'root' had MFA, so
      // one account's root with MFA passed the whole organization. IAM.9 also
      // passes when "root user credentials aren't present in the account"
      // (Organizations central root access); the credential report records that
      // as root_credentials_present (reconciliation found 9 such
      // accounts failing here and passing in Security Hub).
      const assessed = await accountsWithCompleteStage(graphClient, 'iam-access-keys');
      const compliant = new Set(
        readAccountIds(
          await graphClient.executeQuery(`
            ${ROOT_USER_VERTICES}
              .or(has('mfa_enabled', true), has('root_credentials_present', false))
              .values('account_id').dedup()
          `)
        )
      );
      return perAccountResult(
        '1.5',
        { id: 'root-account', type: 'IamUser' },
        assessed,
        compliant,
        (n) => `${n} accounts have no MFA on the root user`
      );
    },
  },
  {
    controlId: '1.10',
    // IAM.5, per account: users with a console password and no MFA.
    evaluate: (graphClient) =>
      perAccountViolations(
        graphClient,
        '1.10',
        { id: 'iam-users', type: 'IamUser' },
        'iam-credential-report',
        `g.V().hasLabel('IamUser').has('password_enabled', true).has('mfa_enabled', false)`,
        (n, users) => `${n} accounts have IAM users with console access and no MFA (${users} users)`
      ),
  },
  {
    controlId: '1.14',
    // IAM.3, per account. Rotation is a function of key age; the previous
    // predicate compared last_used_date, so a long-lived, actively-used key was
    // never flagged. Matches RULE-013 exactly.
    evaluate: (graphClient) =>
      perAccountViolations(
        graphClient,
        '1.14',
        { id: 'iam-access-keys', type: 'AccessKey' },
        'iam-access-keys',
        `g.V().hasLabel('IamUser').out('HAS_ACCESS_KEY').has('status', 'Active').has('key_age_days', gt(${ACCESS_KEY_MAX_AGE_DAYS}))`,
        (n, keys) =>
          `${n} accounts have access keys not rotated in ${ACCESS_KEY_MAX_AGE_DAYS}+ days (${keys} keys)`
      ),
  },
  {
    controlId: '1.12',
    // IAM.22, per account. CIS v3.0.0 1.12 covers console passwords and access
    // keys, at 45 days, active credentials only (a disabled credential is what
    // 1.12 asks for). Keys: last_used_days_ago, as RULE-014; a never-used key's
    // age stands in for idleness. Passwords: from the credential report; a
    // password never used has no password_last_used, so the user's age stands
    // in. The root row has its own controls (1.4-1.7).
    evaluate: (graphClient) => {
      const cutoff = complianceCutoffIso(CREDENTIAL_UNUSED_DAYS);
      return perAccountViolations(
        graphClient,
        '1.12',
        { id: 'iam-credentials', type: 'IamUser' },
        'iam-credential-report',
        `g.V().union(
          __.hasLabel('AccessKey').has('status', 'Active').has('last_used_days_ago', gte(${CREDENTIAL_UNUSED_DAYS})),
          __.hasLabel('IamUser').has('password_enabled', true).not(has('id', '<root_account>')).or(
            has('password_last_used', lt('${cutoff}')),
            and(hasNot('password_last_used'), has('create_date', lt('${cutoff}')))
          )
        )`,
        (n, credentials) =>
          `${n} accounts have credentials unused for ${CREDENTIAL_UNUSED_DAYS}+ days (${credentials} keys or passwords)`
      );
    },
  },
  {
    controlId: '1.15',
    // IAM.2, per account: users should receive permissions only through groups,
    // so any policy attached directly to a user fails, inline or managed. The
    // collector links every user policy with ATTACHED_TO.
    evaluate: async (graphClient) => {
      // Until the collector emits AWS-managed policy vertices, a user whose only
      // direct attachment is an AWS-managed policy has no edge to find.
      if (await awsManagedPoliciesNotYetCollected(graphClient)) {
        return notEvaluated(
          '1.15',
          'No AWS-managed IamPolicy vertices collected yet',
          'iam-users',
          'IamUser'
        );
      }
      return perAccountViolations(
        graphClient,
        '1.15',
        { id: 'iam-users', type: 'IamUser' },
        'iam',
        `g.V().hasLabel('IamUser').where(out('ATTACHED_TO'))`,
        (n, users) =>
          `${n} accounts have IAM users with policies attached directly rather than through a group (${users} users)`
      );
    },
  },
  {
    controlId: '1.8',
    evaluate: async (graphClient) => {
      // IAM.15, per account. An account with no password policy writes no vertex,
      // so counting short policies passed it; it now fails like a short one.
      const assessed = await accountsWithCompleteStage(graphClient, 'iam');
      const compliant = new Set(
        readAccountIds(
          await graphClient.executeQuery(`
            g.V().hasLabel('AccountPasswordPolicy')
              .has('min_password_length', gte(14))
              .values('account_id').dedup()
          `)
        )
      );
      return perAccountResult(
        '1.8',
        { id: 'account-password-policy', type: 'AccountPasswordPolicy' },
        assessed,
        compliant,
        (n) => `${n} accounts have no password policy requiring 14+ characters`
      );
    },
  },
  {
    controlId: '1.9',
    evaluate: async (graphClient) => {
      // IAM.16, per account: fails unless 24 passwords are remembered. No policy
      // at all fails, where it previously passed.
      const assessed = await accountsWithCompleteStage(graphClient, 'iam');
      const compliant = new Set(
        readAccountIds(
          await graphClient.executeQuery(`
            g.V().hasLabel('AccountPasswordPolicy')
              .has('password_reuse_prevention', gte(24))
              .values('account_id').dedup()
          `)
        )
      );
      return perAccountResult(
        '1.9',
        { id: 'account-password-policy', type: 'AccountPasswordPolicy' },
        assessed,
        compliant,
        (n) => `${n} accounts do not prevent reuse of the last 24 passwords`
      );
    },
  },
  {
    controlId: 'KH-1.15',
    evaluate: async (graphClient) => {
      // Per account. A policy that never expires passwords has no MaxPasswordAge,
      // so the property is absent and counting gt(90) passed it; so did no policy.
      const assessed = await accountsWithCompleteStage(graphClient, 'iam');
      const compliant = new Set(
        readAccountIds(
          await graphClient.executeQuery(`
            g.V().hasLabel('AccountPasswordPolicy')
              .has('max_password_age', lte(90))
              .values('account_id').dedup()
          `)
        )
      );
      return perAccountResult(
        'KH-1.15',
        { id: 'account-password-policy', type: 'AccountPasswordPolicy' },
        assessed,
        compliant,
        (n) => `${n} accounts do not expire passwords within 90 days`
      );
    },
  },
  {
    controlId: '2.1.4',
    // CIS 2.1.4 is about the Block Public Access settings, not whether a bucket
    // is public: the previous check counted is_publicly_accessible, so a bucket
    // with every BPA setting off passed as long as its policy was private.
    //
    // The control is met by bucket-level BPA or by account-level BPA (Security
    // Hub S3.8 and S3.1). Only bucket-level is collected so far, so a bucket
    // without all four settings on cannot fail here: its account may cover it.
    evaluate: async (graphClient) => {
      if (await propertyNotYetCollected(graphClient, 'S3Bucket', 'restrict_public_buckets')) {
        return notEvaluated(
          '2.1.4',
          'Bucket Block Public Access settings have not been collected yet',
          's3-buckets',
          'S3Bucket'
        );
      }
      const total = readCount(await graphClient.executeQuery(`g.V().hasLabel('S3Bucket').count()`));
      const fullyBlocked = readCount(
        await graphClient.executeQuery(`
          g.V().hasLabel('S3Bucket')
            .has('block_public_acls', true)
            .has('ignore_public_acls', true)
            .has('block_public_policy', true)
            .has('restrict_public_buckets', true)
            .count()
        `)
      );
      const notFullyBlocked = total - fullyBlocked;
      if (notFullyBlocked > 0) {
        return notEvaluated(
          '2.1.4',
          `${notFullyBlocked} of ${total} S3 buckets do not have all four bucket-level Block ` +
            'Public Access settings on; account-level Block Public Access is not collected yet, ' +
            'so these buckets may still be covered',
          's3-buckets',
          'S3Bucket'
        );
      }
      return {
        status: 'PASS',
        evidence: [
          {
            controlId: '2.1.4',
            resourceId: 's3-buckets',
            resourceType: 'S3Bucket',
            status: 'PASS',
            details: { buckets: total, bucketsWithFullBlockPublicAccess: fullyBlocked },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: [],
      };
    },
  },
  {
    controlId: 'KH-2.2',
    evaluate: async (graphClient) => {
      const query = `
        g.V().hasLabel('S3Bucket')
          .has('versioning_enabled', false)
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = readCount(result);
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: 'KH-2.2',
            resourceId: 's3-buckets',
            resourceType: 'S3Bucket',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { bucketsWithoutVersioning: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: count > 0 ? [`${count} S3 buckets lack versioning`] : [],
      };
    },
  },
  {
    controlId: 'KH-2.3',
    evaluate: async (graphClient) => {
      const query = `
        g.V().hasLabel('S3Bucket')
          .has('default_encryption', false)
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = readCount(result);
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: 'KH-2.3',
            resourceId: 's3-buckets',
            resourceType: 'S3Bucket',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { bucketsWithoutEncryption: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: count > 0 ? [`${count} S3 buckets lack default encryption`] : [],
      };
    },
  },
  {
    controlId: 'KH-2.4',
    evaluate: async (graphClient) => {
      const query = `
        g.V().hasLabel('S3Bucket')
          .has('logging_enabled', false)
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = readCount(result);
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: 'KH-2.4',
            resourceId: 's3-buckets',
            resourceType: 'S3Bucket',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { bucketsWithoutLogging: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: count > 0 ? [`${count} S3 buckets lack access logging`] : [],
      };
    },
  },
  {
    controlId: '2.3.1',
    // RDS.3, per account per Region.
    evaluate: (graphClient) =>
      perAccountRegionViolations(
        graphClient,
        '2.3.1',
        { id: 'rds-instances', type: 'RdsInstance' },
        'rds',
        `g.V().hasLabel('RdsInstance').has('storage_encrypted', false)`,
        (n, instances) =>
          `${n} account/regions have unencrypted RDS instances (${instances} instances)`
      ),
  },
  {
    controlId: 'KH-2.8',
    evaluate: async (graphClient) => {
      const query = `
        g.V().hasLabel('RdsInstance')
          .has('backup_retention_period', lt(7))
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = readCount(result);
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: 'KH-2.8',
            resourceId: 'rds-instances',
            resourceType: 'RdsInstance',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { instancesWithShortRetention: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: count > 0 ? [`${count} RDS instances have backup retention < 7 days`] : [],
      };
    },
  },
  {
    controlId: '2.3.3',
    // RDS.2, per account per Region.
    evaluate: (graphClient) =>
      perAccountRegionViolations(
        graphClient,
        '2.3.3',
        { id: 'rds-instances', type: 'RdsInstance' },
        'rds',
        `g.V().hasLabel('RdsInstance').has('publicly_accessible', true)`,
        (n, instances) =>
          `${n} account/regions have publicly accessible RDS instances (${instances} instances)`
      ),
  },
  {
    controlId: 'KH-2.10',
    evaluate: async (graphClient) => {
      const query = `
        g.V().hasLabel('RdsInstance')
          .has('deletion_protection', false)
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = readCount(result);
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: 'KH-2.10',
            resourceId: 'rds-instances',
            resourceType: 'RdsInstance',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { instancesWithoutDeletionProtection: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: count > 0 ? [`${count} RDS instances lack deletion protection`] : [],
      };
    },
  },
  {
    controlId: '3.1',
    evaluate: async (graphClient) => {
      // CloudTrail.1, per account: at least one multi-Region trail that is logging
      // and captures read and write management events. The previous check passed
      // the organization if any account had any multi-Region trail, logging or not.
      if (await propertyNotYetCollected(graphClient, 'CloudTrail', 'logs_all_management_events')) {
        return notEvaluated(
          '3.1',
          'No CloudTrail vertex records logs_all_management_events yet',
          'cloudtrail-trails',
          'CloudTrail'
        );
      }
      const assessed = await accountsWithCompleteStage(graphClient, 'cloudtrail');
      const compliant = await accountsCoveredByTrail(
        graphClient,
        assessed,
        `.has('is_multi_region_trail', true).has('logs_all_management_events', true).where(out('HAS_STATUS').has('is_logging', true))`
      );
      return perAccountResult(
        '3.1',
        { id: 'cloudtrail-trails', type: 'CloudTrail' },
        assessed,
        compliant,
        (n) =>
          `${n} accounts have no logging multi-Region trail capturing read and write management events`
      );
    },
  },
  {
    controlId: '3.2',
    // CloudTrail.4, per account (see perAccountTrailViolations).
    evaluate: (graphClient) =>
      perAccountTrailViolations(
        graphClient,
        '3.2',
        { id: 'cloudtrail', type: 'CloudTrail' },
        `.has('log_file_validation_enabled', false)`,
        (n, trails) =>
          `${n} accounts have CloudTrail trails without log file validation (${trails} trails)`
      ),
  },
  {
    controlId: '3.5',
    // CloudTrail.2, per account. It fails a trail whose KmsKeyId isn't defined;
    // an undefined KmsKeyId is written as no property at all.
    evaluate: (graphClient) =>
      perAccountTrailViolations(
        graphClient,
        '3.5',
        { id: 'cloudtrail-trails', type: 'CloudTrail' },
        `.or(hasNot('kms_key_id'), has('kms_key_id', ''))`,
        (n, trails) => `${n} accounts have trails not encrypted with a KMS key (${trails} trails)`
      ),
  },
  {
    controlId: 'KH-3.4',
    evaluate: async (graphClient) => {
      // DescribeTrails omits CloudWatchLogsLogGroupArn for a trail with no log
      // group, and normalizeProperties drops undefined -- so the property is
      // absent, never ''. Matching '' alone counted nothing and reported PASS
      // for an organization trail that sends nothing to CloudWatch Logs.
      const query = `
        g.V().hasLabel('CloudTrail')
          .or(
            has('cloudwatch_logs_log_group_arn', ''),
            hasNot('cloudwatch_logs_log_group_arn')
          )
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = readCount(result);
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: 'KH-3.4',
            resourceId: 'cloudtrail',
            resourceType: 'CloudTrail',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { trailsWithoutCloudWatchLogs: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: count > 0 ? [`${count} CloudTrail trails not sending to CloudWatch Logs`] : [],
      };
    },
  },
  {
    controlId: '3.7',
    // EC2.6, per account per Region: every VPC needs an active flow log
    // capturing REJECT traffic (trafficType REJECT; ALL includes it).
    evaluate: async (graphClient) => {
      if (await propertyNotYetCollected(graphClient, 'Vpc', 'flow_logs_capture_rejects')) {
        return notEvaluated(
          '3.7',
          'Flow log traffic types have not been collected yet',
          'vpcs',
          'Vpc'
        );
      }
      return perAccountRegionViolations(
        graphClient,
        '3.7',
        { id: 'vpcs', type: 'Vpc' },
        'network',
        `g.V().hasLabel('Vpc').not(has('flow_logs_capture_rejects', true))`,
        (n, vpcs) =>
          `${n} account/regions have VPCs without a flow log capturing rejected traffic (${vpcs} VPCs)`
      );
    },
  },
  {
    controlId: '3.3',
    evaluate: async (graphClient) => {
      // Config.1, per account per Region: a recorder that is recording, records all
      // supported resource types, and uses the service-linked role
      // AWSServiceRoleForConfig (includeConfigServiceLinkedRoleCheck defaults to
      // true). The previous check passed the org if any recorder existed anywhere.
      const assessed = await accountRegionPairs(graphClient, freshCoverage('config'), 'region');
      const compliant = new Set(
        await accountRegionPairs(
          graphClient,
          `g.V().hasLabel('ConfigRecorder').has('recording', true).has('recording_all_supported', true).has('role_arn', endingWith('/AWSServiceRoleForConfig'))`,
          'collection_region'
        )
      );
      return perAccountRegionResult(
        '3.3',
        { id: 'config-recorders', type: 'ConfigRecorder' },
        assessed,
        compliant,
        (n) =>
          `${n} account/regions have no recording Config recorder for all resources using the service-linked role`
      );
    },
  },
  {
    controlId: 'KH-4.1',
    evaluate: async (graphClient) => {
      // Per account per Region, matching RULE-017. A region with no detector has a
      // synthetic MISSING vertex, which is not ENABLED. The previous check passed
      // the org if any detector anywhere was enabled.
      const assessed = await accountRegionPairs(graphClient, freshCoverage('guardduty'), 'region');
      const compliant = new Set(
        await accountRegionPairs(
          graphClient,
          `g.V().hasLabel('GuardDutyDetector').has('status', 'ENABLED')`,
          'collection_region'
        )
      );
      return perAccountRegionResult(
        'KH-4.1',
        { id: 'guardduty-detectors', type: 'GuardDutyDetector' },
        assessed,
        compliant,
        (n) => `${n} account/regions do not have an enabled GuardDuty detector`
      );
    },
  },
  {
    controlId: '4.16',
    evaluate: async (graphClient) => {
      // Per account per Region (the CIS audit repeats for each Region). Security
      // Hub lists this as manual, since it cannot report itself disabled; the
      // collector reads DescribeHub. The previous check passed the org off any hub.
      const assessed = await accountRegionPairs(
        graphClient,
        freshCoverage('securityhub'),
        'region'
      );
      const compliant = new Set(
        await accountRegionPairs(
          graphClient,
          `g.V().hasLabel('SecurityHub').has('enabled', true)`,
          'collection_region'
        )
      );
      return perAccountRegionResult(
        '4.16',
        { id: 'security-hub', type: 'SecurityHub' },
        assessed,
        compliant,
        (n) => `${n} account/regions do not have Security Hub enabled`
      );
    },
  },
  {
    controlId: '5.1',
    // Per account per Region.
    evaluate: async (graphClient) => {
      // EC2.21 fails a NACL whose inbound entry allows 0.0.0.0/0 or ::/0 to ports
      // 22 or 3389, and does not generate findings for a default NACL. The
      // control page says TCP; the Config rule it runs on
      // (nacl-no-unrestricted-ssh-rdp) flags "TCP or UDP", so UDP stays --
      // matching tcp only would pass a NACL Security Hub fails. Rule ordering is
      // not modelled, so a deny ahead of an allow still reports, same as there.
      // This used to be IPv4-only, with ::/0 split out as KH-5.3 on the belief
      // that EC2.21 was; it is not, and KH-5.3 is removed.
      // Protocol -1 carries no PortRange, which the collector records as 0-0.
      //
      // Deliberately NOT filtered on ASSOCIATED_WITH, unlike KH-5.1.
      // EC2.21 evaluates every NACL as a standalone resource, so filtering to
      // the associated ones would let this control PASS where Security Hub
      // FAILs. A CIS-numbered control has to reconcile against Security Hub;
      // the Khalifa controls are ours to make smarter. An orphaned open NACL is
      // not real exposure, so expect a little noise here in exchange for that
      // parity.
      if (await networkAclEntriesMissing(graphClient)) {
        return notEvaluated('5.1', 'NetworkAcl vertices exist with no NetworkAclEntry vertices');
      }
      return perAccountRegionViolations(
        graphClient,
        '5.1',
        { id: 'network-acls', type: 'NetworkAcl' },
        'network',
        `g.V().hasLabel('NetworkAclEntry')
          .has('direction', 'ingress')
          .has('rule_action', 'allow')
          .has('cidr_block', within('0.0.0.0/0', '::/0'))
          .has('protocol', within('tcp', 'udp', '-1'))
          .${ADMIN_PORT_RANGE_PREDICATE}
          .out('PART_OF').hasLabel('NetworkAcl')
          .not(has('is_default', true))
          .dedup()`,
        (n, nacls) =>
          `${n} account/regions have network ACLs allowing 0.0.0.0/0 or ::/0 on port 22 or 3389 (${nacls} NACLs)`
      );
    },
  },
  {
    controlId: 'KH-5.1',
    evaluate: async (graphClient) => {
      // The database-port half of what Khalifa's 5.1 used to claim before it was
      // scoped to EC2.21. v3.0.0 covers only 22 and 3389, so these live here
      // rather than under a CIS id. Both address families, unlike CIS 5.1 --
      // this control is ours, so the benchmark's IPv4 wording does not bind it.
      // TCP and -1 only: 1433, 3306 and 5432 over UDP are not these databases.
      if (await networkAclEntriesMissing(graphClient)) {
        return notEvaluated('KH-5.1', 'NetworkAcl vertices exist with no NetworkAclEntry vertices');
      }
      const query = `
        g.V().hasLabel('NetworkAclEntry')
          .has('direction', 'ingress')
          .has('rule_action', 'allow')
          .has('cidr_block', within('0.0.0.0/0', '::/0'))
          .has('protocol', within('tcp', '-1'))
          .or(
            has('port_from', 0).has('port_to', 0),
            has('port_from', lte(1433)).has('port_to', gte(1433)),
            has('port_from', lte(3306)).has('port_to', gte(3306)),
            has('port_from', lte(5432)).has('port_to', gte(5432))
          )
          .out('PART_OF').hasLabel('NetworkAcl')
          .where(outE('ASSOCIATED_WITH'))
          .dedup()
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = readCount(result);
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: 'KH-5.1',
            resourceId: 'network-acls',
            resourceType: 'NetworkAcl',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { naclsWithOpenDatabasePorts: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues:
          count > 0
            ? [`${count} network ACLs allow unrestricted ingress on port 1433, 3306 or 5432`]
            : [],
      };
    },
  },
  {
    controlId: '1.20',
    // IAM.28, per account per Region: an ACTIVE external-access analyzer. The
    // collector emits a synthetic MISSING analyzer when a Region has none. The
    // previous check could not tell "an analyzer in every collected Region"
    // from "one analyzer somewhere"; collection_region now can.
    evaluate: async (graphClient) => {
      const assessed = await accountRegionPairs(
        graphClient,
        freshCoverage('access-analyzer'),
        'region'
      );
      const compliant = new Set(
        await accountRegionPairs(
          graphClient,
          `g.V().hasLabel('AccessAnalyzer').has('status', 'ACTIVE')`,
          'collection_region'
        )
      );
      return perAccountRegionResult(
        '1.20',
        { id: 'access-analyzers', type: 'AccessAnalyzer' },
        assessed,
        compliant,
        (n) => `${n} account/regions have no ACTIVE IAM Access Analyzer`
      );
    },
  },
  {
    controlId: '3.6',
    // KMS.4, per account per Region (Config rule cmk-backing-key-rotation-enabled):
    // enabled customer keys must rotate. Rotation is not supported for
    // asymmetric or HMAC keys, imported key material, or custom key stores, so
    // those are out of scope.
    evaluate: async (graphClient) => {
      if (await propertyNotYetCollected(graphClient, 'KmsKey', 'key_spec')) {
        return notEvaluated(
          '3.6',
          'KMS key specs have not been collected yet',
          'kms-keys',
          'KmsKey'
        );
      }
      return perAccountRegionViolations(
        graphClient,
        '3.6',
        { id: 'kms-keys', type: 'KmsKey' },
        'kms',
        `g.V().hasLabel('KmsKey').has('key_manager', 'CUSTOMER').has('key_state', 'Enabled').has('key_spec', 'SYMMETRIC_DEFAULT').has('origin', 'AWS_KMS').hasNot('custom_key_store_id').or(has('rotation_enabled', false), hasNot('rotation_enabled'))`,
        (n, keys) =>
          `${n} account/regions have rotatable customer-managed KMS keys without rotation (${keys} keys)`,
        // Keys whose policy denies DescribeKey to the collector: rotation unknown.
        `g.V().hasLabel('KmsKey').has('collection_restricted', true)`
      );
    },
  },
  {
    controlId: '5.6',
    // EC2.8, per account per Region. Broader than RULE-024 deliberately: the
    // rule fires only when an IMDSv1 instance also holds an IAM role; the
    // control asks whether IMDSv2 is enforced at all. Terminated instances
    // linger in DescribeInstances output and can't be remediated, so are out.
    evaluate: (graphClient) =>
      perAccountRegionViolations(
        graphClient,
        '5.6',
        { id: 'ec2-instances', type: 'Ec2Instance' },
        'ec2-instances',
        `g.V().hasLabel('Ec2Instance').has('metadata_http_tokens', 'optional').not(has('state', within('terminated', 'shutting-down')))`,
        (n, instances) =>
          `${n} account/regions have EC2 instances still accepting IMDSv1 (${instances} instances)`
      ),
  },
  {
    controlId: 'KH-5.7',
    evaluate: async (graphClient) => {
      // Counts VPCs with no interface or gateway endpoint at all. The benchmark
      // asks that endpoints be used for AWS service access; without collected
      // per-service traffic there is no way to prove which services bypass one,
      // so a VPC with zero endpoints is the defensible signal.
      const query = `
        g.V().hasLabel('Vpc')
          .not(__.out('HAS_ENDPOINT').hasLabel('VpcEndpoint'))
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = readCount(result);
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: 'KH-5.7',
            resourceId: 'vpcs',
            resourceType: 'Vpc',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { vpcsWithoutEndpoints: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: count > 0 ? [`${count} VPCs have no VPC endpoints configured`] : [],
      };
    },
  },
  {
    controlId: 'KH-2.11',
    evaluate: async (graphClient) => {
      // A missing property means the field was absent from the AWS response, not
      // that the setting is on. normalizeProperties drops undefined, so hasNot is
      // what stops an unassessable resource counting as compliant.
      const query = `
        g.V().hasLabel('RedshiftCluster')
          .not(has('status', within('deleting', 'creating')))
          .or(has('encrypted', false), hasNot('encrypted'))
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = readCount(result);
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: 'KH-2.11',
            resourceId: 'redshift-clusters',
            resourceType: 'RedshiftCluster',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { clustersNotEncrypted: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: count > 0 ? [`${count} Redshift clusters are not encrypted at rest`] : [],
      };
    },
  },
  {
    controlId: 'KH-2.12',
    evaluate: async (graphClient) => {
      // publicly_accessible true puts the cluster on a routable endpoint.
      // A missing property means the field was absent from the AWS response, not
      // that the setting is on. normalizeProperties drops undefined, so hasNot is
      // what stops an unassessable resource counting as compliant.
      const query = `
        g.V().hasLabel('RedshiftCluster')
          .not(has('status', within('deleting', 'creating')))
          .or(has('publicly_accessible', true), hasNot('publicly_accessible'))
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = readCount(result);
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: 'KH-2.12',
            resourceId: 'redshift-clusters',
            resourceType: 'RedshiftCluster',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { clustersPubliclyAccessible: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues:
          count > 0 ? [`${count} Redshift clusters are publicly accessible or unassessable`] : [],
      };
    },
  },
  {
    controlId: 'KH-2.13',
    evaluate: async (graphClient) => {
      // Scoped to redis/valkey: memcached cannot do at-rest encryption at all,
      // so hasNot would flag every memcached cluster permanently with no
      // remediation available -- the same error as counting terminated EC2
      // instances. Both legs, transit and at rest, are required.
      // A missing property means the field was absent from the AWS response, not
      // that the setting is on. normalizeProperties drops undefined, so hasNot is
      // what stops an unassessable resource counting as compliant.
      const query = `
        g.V().hasLabel('ElastiCacheCluster')
          .has('engine', within('redis', 'valkey'))
          .not(has('status', within('deleting', 'creating')))
          .or(
            has('transit_encryption', false),
            hasNot('transit_encryption'),
            has('at_rest_encryption', false),
            hasNot('at_rest_encryption')
          )
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = readCount(result);
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: 'KH-2.13',
            resourceId: 'elasticache-clusters',
            resourceType: 'ElastiCacheCluster',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { clustersMissingEncryption: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues:
          count > 0 ? [`${count} ElastiCache clusters lack transit or at-rest encryption`] : [],
      };
    },
  },
  {
    controlId: 'KH-2.14',
    evaluate: async (graphClient) => {
      // A missing property means the field was absent from the AWS response, not
      // that the setting is on. normalizeProperties drops undefined, so hasNot is
      // what stops an unassessable resource counting as compliant.
      const query = `
        g.V().hasLabel('OpenSearchDomain')
          .or(has('encryption_at_rest', false), hasNot('encryption_at_rest'))
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = readCount(result);
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: 'KH-2.14',
            resourceId: 'opensearch-domains',
            resourceType: 'OpenSearchDomain',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { domainsNotEncrypted: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: count > 0 ? [`${count} OpenSearch domains are not encrypted at rest`] : [],
      };
    },
  },
  {
    controlId: 'KH-2.15',
    evaluate: async (graphClient) => {
      // A missing property means the field was absent from the AWS response, not
      // that the setting is on. normalizeProperties drops undefined, so hasNot is
      // what stops an unassessable resource counting as compliant.
      const query = `
        g.V().hasLabel('OpenSearchDomain')
          .or(has('enforce_https', false), hasNot('enforce_https'))
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = readCount(result);
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: 'KH-2.15',
            resourceId: 'opensearch-domains',
            resourceType: 'OpenSearchDomain',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { domainsNotEnforcingHttps: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: count > 0 ? [`${count} OpenSearch domains do not enforce HTTPS`] : [],
      };
    },
  },
  {
    controlId: 'KH-2.16',
    evaluate: async (graphClient) => {
      // A missing property means the field was absent from the AWS response, not
      // that the setting is on. normalizeProperties drops undefined, so hasNot is
      // what stops an unassessable resource counting as compliant.
      const query = `
        g.V().hasLabel('OpenSearchDomain')
          .or(has('node_to_node_encryption', false), hasNot('node_to_node_encryption'))
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = readCount(result);
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: 'KH-2.16',
            resourceId: 'opensearch-domains',
            resourceType: 'OpenSearchDomain',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { domainsWithoutNodeEncryption: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: count > 0 ? [`${count} OpenSearch domains lack node-to-node encryption`] : [],
      };
    },
  },
  {
    controlId: '3.4',
    // CloudTrail.7, per account of the trail. The trail records its bucket by
    // name, not by an edge. A bucket whose logging_enabled is absent counts too:
    // the collector derives it from GetBucketLogging, and a failed call leaves
    // the property off entirely. Bucket names are resolved first, in two short
    // queries: joining every trail against every S3Bucket inside one traversal
    // timed out on Neptune (30 s, 2026-10-14).
    evaluate: async (graphClient) => {
      const trailBuckets = readBucketNames(
        await graphClient.executeQuery(
          `g.V().hasLabel('CloudTrail').values('s3_bucket_name').dedup()`
        )
      );
      const unlogged =
        trailBuckets.length === 0
          ? []
          : readBucketNames(
              await graphClient.executeQuery(
                `g.V().hasLabel('S3Bucket').has('name', within(${gremlinStrings(trailBuckets)}))
                  .or(has('logging_enabled', false), hasNot('logging_enabled'))
                  .values('name').dedup()`
              )
            );
      return perAccountTrailViolations(
        graphClient,
        '3.4',
        { id: 'cloudtrail-buckets', type: 'S3Bucket' },
        unlogged.length === 0
          ? '.limit(0)'
          : `.has('s3_bucket_name', within(${gremlinStrings(unlogged)}))`,
        (n, trails) =>
          `${n} accounts have trails whose S3 bucket has access logging disabled (${trails} trails)`
      );
    },
  },
  {
    controlId: 'KH-3.11',
    evaluate: async (graphClient) => {
      // Same join shape as 3.4, against the Config delivery channel's bucket.
      // default_encryption is derived from GetBucketEncryption, so an absent
      // property means the call failed, not that encryption is off.
      const query = `
        g.V().hasLabel('ConfigDeliveryChannel').has('s3_bucket_name')
          .values('s3_bucket_name').dedup().as('channelBucket')
          .V().hasLabel('S3Bucket').as('bucket')
          .where('bucket', eq('channelBucket')).by('name').by()
          .or(has('default_encryption', false), hasNot('default_encryption'))
          .dedup()
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = readCount(result);
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: 'KH-3.11',
            resourceId: 'config-delivery-buckets',
            resourceType: 'S3Bucket',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { configBucketsWithoutEncryption: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: count > 0 ? [`${count} AWS Config delivery buckets are not encrypted`] : [],
      };
    },
  },
  {
    controlId: 'KH-EKS-1',
    evaluate: async (graphClient) => {
      // Mirrors RULE-019. endpoint_world_open is derived by the collector from
      // public_access_cidrs, so it already means "0.0.0.0/0 is in the list".
      const query = `
        g.V().hasLabel('EksCluster')
          .has('endpoint_public_access', true)
          .has('endpoint_world_open', true)
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = readCount(result);
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: 'KH-EKS-1',
            resourceId: 'eks-clusters',
            resourceType: 'EksCluster',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { clustersWithWorldOpenEndpoint: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues:
          count > 0 ? [`${count} EKS clusters expose a public API endpoint to the world`] : [],
      };
    },
  },
  {
    controlId: 'KH-SEC-1',
    evaluate: async (graphClient) => {
      // Mirrors RULE-016. secret_grant_scope is computed at collection time:
      // wildcard means Resource * or a Secrets Manager ARN containing *.
      const query = `
        g.V().hasLabel('IamPolicyStatement')
          .has('effect', 'Allow')
          .has('grants_secret_read', true)
          .has('secret_grant_scope', 'wildcard')
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = readCount(result);
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: 'KH-SEC-1',
            resourceId: 'iam-policy-statements',
            resourceType: 'IamPolicyStatement',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { statementsGrantingWildcardSecretRead: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues:
          count > 0
            ? [`${count} IAM policy statements grant secret read on a wildcard resource`]
            : [],
      };
    },
  },
  {
    controlId: 'KH-SEC-2',
    evaluate: async (graphClient) => {
      // Mirrors RULE-012. The DSPM scanner classifies content in memory and
      // persists only counts, so secret_count is the whole signal available.
      const query = `
        g.V().hasLabel('DataClassificationFinding')
          .has('secret_count', gt(0))
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = readCount(result);
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: 'KH-SEC-2',
            resourceId: 'data-classification-findings',
            resourceType: 'DataClassificationFinding',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { findingsContainingSecrets: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues:
          count > 0 ? [`${count} objects or function environments contain detected secrets`] : [],
      };
    },
  },
  {
    controlId: 'KH-5.6',
    evaluate: async (graphClient) => {
      // The ports named in this control's evidenceRequirements. 22 and 3389 are
      // deliberately absent: CIS 5.2 and 5.3 own those, and repeating them here
      // would report the same group twice across two frameworks.
      const query = `
        g.V().hasLabel('SecurityGroupRule')
          .has('direction', 'ingress')
          .has('cidr_block', within('0.0.0.0/0', '::/0'))
          .has('protocol', within('tcp', '-1'))
          .or(
            has('port_from', 0).has('port_to', 0),
            has('port_from', lte(1433)).has('port_to', gte(1433)),
            has('port_from', lte(3306)).has('port_to', gte(3306)),
            has('port_from', lte(5432)).has('port_to', gte(5432)),
            has('port_from', lte(6379)).has('port_to', gte(6379)),
            has('port_from', lte(9200)).has('port_to', gte(9200)),
            has('port_from', lte(27017)).has('port_to', gte(27017))
          )
          .out('PART_OF').hasLabel('SecurityGroup').dedup()
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = readCount(result);
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: 'KH-5.6',
            resourceId: 'security-groups',
            resourceType: 'SecurityGroup',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { groupsExposingCommonPorts: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues:
          count > 0
            ? [`${count} security groups expose a database or search port to the internet`]
            : [],
      };
    },
  },
  {
    controlId: 'KH-3.5',
    evaluate: async (graphClient) => {
      // Same bucket-name join as 3.4: the trail records its bucket as a string,
      // not an edge. is_publicly_accessible comes from GetBucketPolicyStatus, so
      // an absent property means that call failed rather than the bucket being
      // private.
      const query = `
        g.V().hasLabel('CloudTrail').has('s3_bucket_name')
          .values('s3_bucket_name').dedup().as('trailBucket')
          .V().hasLabel('S3Bucket').as('bucket')
          .where('bucket', eq('trailBucket')).by('name').by()
          .or(has('is_publicly_accessible', true), hasNot('is_publicly_accessible'))
          .dedup()
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = readCount(result);
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: 'KH-3.5',
            resourceId: 'cloudtrail-buckets',
            resourceType: 'S3Bucket',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { trailBucketsPublicOrUnassessable: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues:
          count > 0 ? [`${count} CloudTrail S3 buckets are public or could not be assessed`] : [],
      };
    },
  },
  {
    controlId: 'KH-PATH-1',
    evaluate: async (graphClient) => {
      // Mirrors RULE-005: walk out from the Internet vertex up to four hops and
      // count the crown jewels reachable. simplePath stops the traversal
      // revisiting a vertex, which is what keeps a cyclic graph terminating.
      const query = `
        g.V().hasLabel('Internet')
          .repeat(outE().inV().simplePath())
          .until(or(has('crown_jewel', true), loops().is(4)))
          .has('crown_jewel', true)
          .dedup()
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = readCount(result);
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: 'KH-PATH-1',
            resourceId: 'crown-jewels',
            resourceType: 'Resource',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { crownJewelsReachableFromInternet: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: count > 0 ? [`${count} crown-jewel resources are reachable from the internet`] : [],
      };
    },
  },
  {
    controlId: '2.1.2',
    // S3.20, per account. MFA Delete only exists on versioned buckets, so
    // unversioned ones are out of scope rather than failures -- matching
    // Security Hub. Known gap: S3.20 also skips buckets with a lifecycle
    // configuration; the collector does not record lifecycle rules, so such a
    // bucket reports FAIL here and PASS there.
    evaluate: async (graphClient) => {
      if (await propertyNotYetCollected(graphClient, 'S3Bucket', 'mfa_delete_enabled')) {
        return notEvaluated(
          '2.1.2',
          'S3Bucket vertices predate mfa_delete_enabled',
          's3-buckets',
          'S3Bucket'
        );
      }
      return perAccountViolations(
        graphClient,
        '2.1.2',
        { id: 's3-buckets', type: 'S3Bucket' },
        's3',
        `g.V().hasLabel('S3Bucket').has('versioning_enabled', true).or(has('mfa_delete_enabled', false), hasNot('mfa_delete_enabled'))`,
        (n, buckets) =>
          `${n} accounts have versioned S3 buckets without MFA Delete (${buckets} buckets)`
      );
    },
  },
  {
    controlId: '2.3.2',
    // RDS.13, per account per Region. auto_minor_version_upgrade comes straight
    // from DescribeDBInstances; absent means the field was missing from the
    // response, which is not the same as enabled.
    evaluate: async (graphClient) => {
      if (await propertyNotYetCollected(graphClient, 'RdsInstance', 'auto_minor_version_upgrade')) {
        return notEvaluated(
          '2.3.2',
          'RdsInstance vertices predate auto_minor_version_upgrade',
          'rds-instances',
          'RdsInstance'
        );
      }
      return perAccountRegionViolations(
        graphClient,
        '2.3.2',
        { id: 'rds-instances', type: 'RdsInstance' },
        'rds',
        `g.V().hasLabel('RdsInstance').or(has('auto_minor_version_upgrade', false), hasNot('auto_minor_version_upgrade'))`,
        (n, instances) =>
          `${n} account/regions have RDS instances not auto-applying minor upgrades (${instances} instances)`
      );
    },
  },
  {
    controlId: '3.8',
    evaluate: async (graphClient) => {
      // S3.22, per account: a multi-Region trail logging S3 object write events
      // for every bucket. The property is absent when GetEventSelectors failed for
      // a trail, so if no trail carries it the answer is unknown, not FAIL.
      if (await propertyNotYetCollected(graphClient, 'CloudTrail', 'logs_all_s3_object_writes')) {
        return notEvaluated(
          '3.8',
          'No CloudTrail vertex records logs_all_s3_object_writes: selectors not collected or unreadable',
          'cloudtrail-trails',
          'CloudTrail'
        );
      }
      const assessed = await accountsWithCompleteStage(graphClient, 'cloudtrail');
      const compliant = await accountsCoveredByTrail(
        graphClient,
        assessed,
        `.has('is_multi_region_trail', true).has('logs_all_s3_object_writes', true)`
      );
      return perAccountResult(
        '3.8',
        { id: 'cloudtrail-trails', type: 'CloudTrail' },
        assessed,
        compliant,
        (n) => `${n} accounts have no multi-Region trail logging S3 object writes for every bucket`
      );
    },
  },
  {
    controlId: '3.9',
    evaluate: async (graphClient) => {
      // S3.23, per account: as 3.8, for read events.
      if (await propertyNotYetCollected(graphClient, 'CloudTrail', 'logs_all_s3_object_reads')) {
        return notEvaluated(
          '3.9',
          'No CloudTrail vertex records logs_all_s3_object_reads: selectors not collected or unreadable',
          'cloudtrail-trails',
          'CloudTrail'
        );
      }
      const assessed = await accountsWithCompleteStage(graphClient, 'cloudtrail');
      const compliant = await accountsCoveredByTrail(
        graphClient,
        assessed,
        `.has('is_multi_region_trail', true).has('logs_all_s3_object_reads', true)`
      );
      return perAccountResult(
        '3.9',
        { id: 'cloudtrail-trails', type: 'CloudTrail' },
        assessed,
        compliant,
        (n) => `${n} accounts have no multi-Region trail logging S3 object reads for every bucket`
      );
    },
  },
  {
    controlId: '1.17',
    // IAM.18, per account: an account fails with no user, group or role carrying
    // AWSSupportAccess (policyUsageType ANY); one account's support role says
    // nothing about another's.
    evaluate: async (graphClient) => {
      if (await awsManagedPoliciesNotYetCollected(graphClient)) {
        return notEvaluated(
          '1.17',
          'No AWS-managed IamPolicy vertices collected yet',
          'iam-roles',
          'IamRole'
        );
      }
      const assessed = await accountsWithCompleteStage(graphClient, 'iam');
      const withSupportRole = new Set(
        readAccountIds(
          await graphClient.executeQuery(`
            g.V().hasLabel(within('IamRole', 'IamUser', 'IamGroup'))
              .where(out('ATTACHED_TO').has('arn', 'arn:aws:iam::aws:policy/AWSSupportAccess'))
              .values('account_id').dedup()
          `)
        )
      );
      return perAccountResult(
        '1.17',
        { id: 'iam-roles', type: 'IamRole' },
        assessed,
        withSupportRole,
        (n) => `${n} accounts have no role with AWSSupportAccess attached`
      );
    },
  },
  {
    controlId: '1.22',
    // IAM.27, per account: any user, role or group with AWSCloudShellFullAccess,
    // which grants CloudShell file upload and download, a path to exfiltrate data.
    evaluate: async (graphClient) => {
      if (await awsManagedPoliciesNotYetCollected(graphClient)) {
        return notEvaluated(
          '1.22',
          'No AWS-managed IamPolicy vertices collected yet',
          'iam-identities',
          'IamRole'
        );
      }
      return perAccountViolations(
        graphClient,
        '1.22',
        { id: 'iam-identities', type: 'IamRole' },
        'iam',
        `g.V().hasLabel(within('IamUser', 'IamRole', 'IamGroup')).where(out('ATTACHED_TO').has('arn', 'arn:aws:iam::aws:policy/AWSCloudShellFullAccess'))`,
        (n, identities) =>
          `${n} accounts have identities with AWSCloudShellFullAccess attached (${identities} identities)`
      );
    },
  },
  {
    controlId: 'KH-3.10',
    evaluate: async (graphClient) => {
      // allSupported used to live inside the stringified recording_group
      // object, where Gremlin could not reach it. It is a scalar now.
      if (await propertyNotYetCollected(graphClient, 'ConfigRecorder', 'recording_all_supported')) {
        return notEvaluated(
          'KH-3.10',
          'ConfigRecorder vertices predate recording_all_supported',
          'config-recorders',
          'ConfigRecorder'
        );
      }
      const query = `
        g.V().hasLabel('ConfigRecorder')
          .or(has('recording_all_supported', false), hasNot('recording_all_supported'))
          .count()
      `;
      const count = readCount(await graphClient.executeQuery(query));
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: 'KH-3.10',
            resourceId: 'config-recorders',
            resourceType: 'ConfigRecorder',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { recordersNotRecordingAllTypes: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues:
          count > 0
            ? [`${count} AWS Config recorders do not record all supported resource types`]
            : [],
      };
    },
  },
  {
    controlId: '5.2',
    // EC2.53, per account per Region.
    evaluate: (graphClient) =>
      perAccountRegionViolations(
        graphClient,
        '5.2',
        { id: 'security-groups', type: 'SecurityGroup' },
        'security-groups',
        `g.V().hasLabel('SecurityGroupRule')
          .has('direction', 'ingress')
          .has('cidr_block', '0.0.0.0/0')
          .has('protocol', within('tcp', '-1'))
          .${ADMIN_PORT_RANGE_PREDICATE}
          .out('PART_OF').hasLabel('SecurityGroup').dedup()`,
        (n, groups) =>
          `${n} account/regions have security groups allowing 0.0.0.0/0 on port 22 or 3389 (${groups} groups)`
      ),
  },
  {
    controlId: '5.3',
    // EC2.54, per account per Region. CIS v3.0.0 splits administration-port
    // exposure by address family: 5.2 is the 0.0.0.0/0 check, 5.3 the ::/0 one.
    evaluate: (graphClient) =>
      perAccountRegionViolations(
        graphClient,
        '5.3',
        { id: 'security-groups', type: 'SecurityGroup' },
        'security-groups',
        `g.V().hasLabel('SecurityGroupRule')
          .has('direction', 'ingress')
          .has('cidr_block', '::/0')
          .has('protocol', within('tcp', '-1'))
          .${ADMIN_PORT_RANGE_PREDICATE}
          .out('PART_OF').hasLabel('SecurityGroup').dedup()`,
        (n, groups) =>
          `${n} account/regions have security groups allowing ::/0 on port 22 or 3389 (${groups} groups)`
      ),
  },
  {
    controlId: '5.4',
    // EC2.2, per account per Region: a VPC's default security group must allow
    // no inbound or outbound traffic. An untouched default group -- self-
    // referencing inbound, allow-all outbound -- fails.
    evaluate: async (graphClient) => {
      if (await propertyNotYetCollected(graphClient, 'SecurityGroup', 'egress_rule_count')) {
        return notEvaluated(
          '5.4',
          'Security group rule counts have not been collected yet',
          'security-groups',
          'SecurityGroup'
        );
      }
      return perAccountRegionViolations(
        graphClient,
        '5.4',
        { id: 'security-groups', type: 'SecurityGroup' },
        'security-groups',
        `g.V().hasLabel('SecurityGroup').has('is_default', true).or(has('ingress_rule_count', gt(0)), has('egress_rule_count', gt(0)))`,
        (n, groups) =>
          `${n} account/regions have default security groups allowing traffic (${groups} groups)`
      );
    },
  },
];

export function getEvaluatorForControl(controlId: string): ComplianceRuleEvaluator | undefined {
  return complianceRuleEvaluators.find((e) => e.controlId === controlId);
}

export function getAllEvaluators(): ComplianceRuleEvaluator[] {
  return complianceRuleEvaluators;
}

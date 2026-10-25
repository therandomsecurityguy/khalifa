'use client';

import Link from 'next/link';
import { Suspense, useEffect, useState, type ReactNode } from 'react';
import { useSearchParams } from 'next/navigation';
import { getAccounts, getSecret, isNotFound } from '@/lib/api';
import { useRequest } from '@/lib/use-request';
import {
  daysSince,
  fixSteps,
  isRotationOff,
  lastAccessedLabel,
  severityCounts,
  sharingLabel,
} from '@/lib/secrets';
import { resourceHref } from '@/lib/routes';
import type { SecretDetail, SecretInventoryItem, SecretReader } from '@/types';
import { SeverityCounts } from '@/components/severity-counts';
import { ErrorState, LoadingState, NotFoundState } from '@/components/states';
import {
  Badge,
  Card,
  LINK,
  PageBody,
  PageHeader,
  SeverityBadge,
  StatusMessage,
  TONES,
  Table,
  Td,
  Th,
} from '@/components/ui';

const BACK = { backHref: '/secrets', backLabel: '← Back to Secrets' };
const KIND_LABEL: Record<SecretInventoryItem['kind'], string> = {
  'secrets-manager': 'Secrets Manager',
  'ssm-parameter': 'SSM SecureString',
  'ssm-plaintext': 'SSM String',
};
const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3 } as const;
const DATE = new Intl.DateTimeFormat('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
// The API checks this too; checking here avoids a request for a bad link.
const SECRET_ARN =
  /^arn:aws(?:-[a-z]+)*:(?:secretsmanager:[a-z0-9-]+:\d{12}:secret:|ssm:[a-z0-9-]+:\d{12}:parameter\/)[\x21-\x7e]{1,512}$/;

function dated(iso: string | null, now: number): string {
  const days = daysSince(iso, now);
  if (!iso || days === null) return 'Never';
  return `${DATE.format(new Date(iso))} · ${days === 0 ? 'today' : `${days} days ago`}`;
}

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <dt className="text-sm font-medium text-gray-500">{label}</dt>
      <dd className="mt-1 text-sm text-gray-900">{children}</dd>
    </div>
  );
}

const SCOPE_LABEL: Record<SecretReader['grants'][number]['scope'], string> = {
  secret: 'This secret',
  pattern: 'Matching pattern',
  all: 'All resources',
  'not-resource': 'All but listed',
};
const POLICY_KIND: Record<SecretReader['grants'][number]['policyKind'], string> = {
  inline: 'Inline',
  managed: 'Customer managed',
  'aws-managed': 'AWS managed',
};
const TYPE_LABEL: Record<SecretReader['type'], string> = {
  role: 'IAM role',
  user: 'IAM user',
  group: 'IAM group',
};

// Broad: reaches the secret without naming it.
function isBroad(reader: SecretReader): boolean {
  return reader.grants.some(
    (grant) => grant.scope === 'all' || grant.scope === 'not-resource' || grant.notAction
  );
}

function ReadersCard({ readers }: { readers: NonNullable<SecretDetail['readers']> }) {
  const [broadOnly, setBroadOnly] = useState(false);
  const shown = broadOnly ? readers.items.filter(isBroad) : readers.items;
  const broad = readers.items.filter(isBroad).length;
  return (
    <Card
      title="Who can read it"
      description="Roles, users and groups in this account whose identity policies allow secretsmanager:GetSecretValue on this secret. Conditions, permission boundaries, SCPs, key policies and principals in other accounts are not evaluated."
      actions={
        readers.items.length > 0 ? (
          <div role="group" aria-label="Show" className="inline-flex rounded-md bg-gray-100 p-0.5">
            {[
              { label: `All (${readers.items.length})`, value: false },
              { label: `Broad only (${broad})`, value: true },
            ].map((option) => (
              <button
                key={option.label}
                type="button"
                aria-pressed={broadOnly === option.value}
                onClick={() => setBroadOnly(option.value)}
                className="rounded px-3 py-1 text-sm font-medium text-gray-600 aria-pressed:bg-white aria-pressed:text-gray-900 aria-pressed:shadow-sm"
              >
                {option.label}
              </button>
            ))}
          </div>
        ) : undefined
      }
      flush
    >
      {readers.unavailable ? (
        <StatusMessage tone="warning" className="m-4">
          Readers could not be worked out right now. Try reloading the page.
        </StatusMessage>
      ) : readers.items.length === 0 ? (
        <p className="px-6 py-5 text-sm text-gray-500">
          No role, user or group in this account has an identity policy that allows reading it.
        </p>
      ) : (
        <>
          <Table caption="Who can read it">
            <thead>
              <tr>
                <Th>Principal</Th>
                <Th>Granted by</Th>
                <Th>Scope</Th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 bg-white">
              {shown.map((reader) => {
                const grant = reader.grants[0];
                return (
                  <tr key={reader.id}>
                    <Td className="align-top">
                      <Link
                        href={resourceHref(reader.id)}
                        className={`[overflow-wrap:anywhere] ${LINK}`}
                      >
                        {reader.name}
                      </Link>
                      <div className="mt-1 flex flex-wrap items-center gap-1.5 text-xs text-gray-500">
                        {TYPE_LABEL[reader.type]}
                        {reader.admin && <Badge tone={TONES.danger}>Admin</Badge>}
                        {reader.mayBeDenied && <Badge tone={TONES.warning}>May be denied</Badge>}
                      </div>
                    </Td>
                    <Td className="align-top">
                      <div className="[overflow-wrap:anywhere]">{grant.policyName}</div>
                      <div className="text-xs text-gray-500">
                        {POLICY_KIND[grant.policyKind]} policy
                        {reader.grants.length > 1 && ` · +${reader.grants.length - 1} more`}
                      </div>
                    </Td>
                    <Td className="align-top">
                      <div className="flex flex-wrap gap-1.5">
                        <Badge
                          tone={
                            grant.scope === 'secret' || grant.scope === 'pattern'
                              ? TONES.neutral
                              : TONES.warning
                          }
                        >
                          {SCOPE_LABEL[grant.scope]}
                        </Badge>
                        {grant.notAction && (
                          <Badge tone={TONES.warning}>All actions but listed</Badge>
                        )}
                        {grant.conditional && <Badge tone={TONES.info}>Conditional</Badge>}
                      </div>
                    </Td>
                  </tr>
                );
              })}
            </tbody>
          </Table>
          {readers.truncated && (
            <p className="border-t border-gray-200 px-6 py-3 text-sm text-gray-500">
              Showing the first {readers.items.length} readers; more exist.
            </p>
          )}
        </>
      )}
    </Card>
  );
}

function rotationText(item: SecretInventoryItem): string {
  if (item.kind !== 'secrets-manager') return 'No rotation (SSM parameter)';
  if (!isRotationOff(item)) return 'On';
  return item.rotationEnabled === null ? 'Off · never configured' : 'Off';
}

function SecretDetailView({ arn }: { arn: string }) {
  const secret = useRequest((signal) => getSecret(arn, { signal }), [arn]);
  const accounts = useRequest((signal) => getAccounts({ signal }), []);
  const now = Date.now();
  // A link to #readers arrives before the card exists; scroll once it renders.
  const loaded = secret.status === 'success';
  useEffect(() => {
    if (loaded && window.location.hash === '#readers') {
      document.getElementById('readers')?.scrollIntoView({ block: 'start' });
    }
  }, [loaded]);

  if (secret.status === 'error') {
    if (isNotFound(secret.error)) {
      return (
        <NotFoundState
          title="Secret"
          message="That secret is not in the graph, or was deleted."
          {...BACK}
        />
      );
    }
    return (
      <>
        <PageHeader title="Secret" {...BACK} />
        <PageBody>
          <ErrorState error={secret.error} onRetry={secret.reload} />
        </PageBody>
      </>
    );
  }
  if (secret.status !== 'success') {
    return (
      <>
        <PageHeader title="Secret" {...BACK} />
        <PageBody>
          <LoadingState label="Loading secret…" />
        </PageBody>
      </>
    );
  }

  const { item, issuesUnavailable, readers } = secret.data;
  const accountName =
    (accounts.status === 'success' &&
      accounts.data.accounts.find((account) => account.id === item.accountId)?.name) ||
    item.accountId;
  const counts = severityCounts(item);
  const steps = fixSteps(item, now);
  const issues = [...item.issues].sort(
    (a, b) =>
      SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] || a.openedAt.localeCompare(b.openedAt)
  );
  const outside = item.sharing?.scope === 'outside';
  const shared = item.sharing?.scope === 'org' || item.sharing?.scope === 'collected';

  return (
    <>
      <PageHeader
        title={item.name}
        {...BACK}
        actions={counts.length > 0 ? <SeverityCounts counts={counts} size="md" /> : undefined}
      />
      <PageBody>
        <div className="mb-6 flex flex-wrap gap-2">
          <Badge tone={TONES.neutral}>{KIND_LABEL[item.kind]}</Badge>
          {item.kind === 'ssm-plaintext' && <Badge tone={TONES.danger}>Stored unencrypted</Badge>}
          {isRotationOff(item) && <Badge tone={TONES.danger}>Rotation off</Badge>}
          {outside && <Badge tone={TONES.danger}>Shared outside the org</Badge>}
          {shared && <Badge tone={TONES.warning}>Shared across accounts</Badge>}
          {item.collectionRestricted && <Badge tone={TONES.warning}>Policy unreadable</Badge>}
        </div>
        {issuesUnavailable && (
          <StatusMessage tone="warning" className="mb-6">
            Open issues could not be loaded, so this list may be incomplete.
          </StatusMessage>
        )}

        <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
          <div className="space-y-6 lg:col-span-2">
            <Card title="Details">
              <dl className="grid grid-cols-1 gap-x-6 gap-y-5 sm:grid-cols-2">
                <Fact label="Account">{accountName}</Fact>
                <Fact label="Region">{item.region}</Fact>
                <Fact label="Env">{item.env ?? 'Untagged'}</Fact>
                <Fact label="Owner">{item.owner ?? 'Untagged'}</Fact>
                <Fact label="Encryption">
                  {item.encryption === 'none'
                    ? 'None: plain-text String parameter'
                    : item.encryption === 'customer-managed'
                      ? 'Customer managed key'
                      : 'AWS managed key'}
                </Fact>
                <Fact label="Rotation">{rotationText(item)}</Fact>
                {item.kind === 'secrets-manager' ? (
                  <>
                    <Fact label="Created">
                      {item.createdAt ? dated(item.createdAt, now) : 'Not collected yet'}
                    </Fact>
                    <Fact label="Last rotated">{dated(item.lastRotated, now)}</Fact>
                    <Fact label="Last accessed">{lastAccessedLabel(item, now)}</Fact>
                  </>
                ) : (
                  <Fact label="Last modified">{dated(item.lastModified, now)}</Fact>
                )}
                <Fact label="Shared with">{sharingLabel(item)}</Fact>
              </dl>
            </Card>

            {readers && (
              <div id="readers" className="scroll-mt-6">
                <ReadersCard readers={readers} />
              </div>
            )}

            <Card
              title="Open issues"
              description="Open issues that name this secret, worst first."
              flush
            >
              {issues.length === 0 ? (
                <p className="px-6 py-5 text-sm text-gray-500">No open issues name this secret.</p>
              ) : (
                <ul className="divide-y divide-gray-200">
                  {issues.map((issue) => {
                    const age = daysSince(issue.openedAt, now);
                    return (
                      <li
                        key={issue.id}
                        className="flex flex-wrap items-center justify-between gap-3 px-6 py-4"
                      >
                        <div className="flex min-w-0 items-center gap-3">
                          <SeverityBadge severity={issue.severity} tone="soft" />
                          <div className="min-w-0">
                            <div className="font-medium text-gray-900">{issue.title}</div>
                            {age !== null && (
                              <div className="text-xs text-gray-500">
                                Open {age === 0 ? 'since today' : `${age} days`}
                              </div>
                            )}
                          </div>
                        </div>
                        <Link
                          href={`/issues/${encodeURIComponent(issue.id)}`}
                          className={`text-sm ${LINK}`}
                        >
                          View issue →
                        </Link>
                      </li>
                    );
                  })}
                </ul>
              )}
            </Card>
          </div>

          <div className="space-y-6">
            <Card title="What to fix">
              {steps.length === 0 ? (
                <p className="text-sm text-gray-500">Nothing to fix from the collected data.</p>
              ) : (
                <ol className="list-decimal space-y-3 pl-5 text-sm text-gray-900">
                  {steps.map((step) => (
                    <li key={step}>{step}</li>
                  ))}
                </ol>
              )}
            </Card>
            <Card title="Explore">
              <Link
                href={`/attack-paths?from=any&to=resource&toResource=${encodeURIComponent(item.id)}&hops=4`}
                className={`text-sm ${LINK}`}
              >
                Attack paths to this secret →
              </Link>
            </Card>
          </div>
        </div>
      </PageBody>
    </>
  );
}

function SecretDetail() {
  const arn = useSearchParams().get('arn') ?? '';
  if (!SECRET_ARN.test(arn)) {
    return (
      <NotFoundState
        title="Secret"
        message="That link does not name a Secrets Manager secret or SSM parameter."
        {...BACK}
      />
    );
  }
  return <SecretDetailView arn={arn} />;
}

export default function SecretDetailPage() {
  return (
    <Suspense fallback={<LoadingState label="Loading…" />}>
      <SecretDetail />
    </Suspense>
  );
}

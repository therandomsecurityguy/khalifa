'use client';

import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { useState, type ReactNode } from 'react';
import {
  deleteRisk,
  formatTimestamp,
  getRisk,
  getSession,
  isNotFound,
  updateRisk,
} from '@/lib/api';
import { useAsyncAction, useRequest } from '@/lib/use-request';
import type { RiskRegisterEntry } from '@/types';
import { ErrorState, LoadingState, NotFoundState } from '@/components/states';
import {
  Badge,
  Card,
  LINK,
  PageBody,
  PageHeader,
  PRIMARY_BUTTON,
  RiskBadge,
  SECONDARY_BUTTON,
  SelectField,
  Spinner,
  TextField,
  TONES,
} from '@/components/ui';

const BACK = { backHref: '/risks', backLabel: '← Back to the risk register' };
const TEXTAREA =
  'mt-1 block w-full resize-y rounded-md border border-gray-300 bg-white px-2.5 py-1.5 text-sm text-gray-900 shadow-xs focus:border-indigo-500 focus:outline-hidden focus:ring-2 focus:ring-indigo-500/20';
const RATINGS = [1, 2, 3, 4, 5];

const STATUS_TONES: Record<RiskRegisterEntry['status'], string> = {
  open: TONES.danger,
  monitoring: TONES.warning,
  accepted: TONES.neutral,
  closed: TONES.success,
};

interface FormState {
  title: string;
  description: string;
  category: RiskRegisterEntry['category'];
  owner: string;
  status: RiskRegisterEntry['status'];
  likelihood: number;
  impact: number;
  residualAssessed: boolean;
  residualLikelihood: number;
  residualImpact: number;
  treatment: RiskRegisterEntry['treatment'];
  acceptanceDate: string;
  reviewCadenceDays: number;
  lastReviewedDate: string;
  linkedIssueIds: string;
  linkedControls: string;
}

const toDateInput = (iso: string | null): string => (iso ? iso.slice(0, 10) : '');
const fromDateInput = (value: string): string | null =>
  value ? new Date(`${value}T00:00:00.000Z`).toISOString() : null;

function formFrom(risk: RiskRegisterEntry): FormState {
  return {
    title: risk.title,
    description: risk.description,
    category: risk.category,
    owner: risk.owner,
    status: risk.status,
    likelihood: risk.inherent.likelihood,
    impact: risk.inherent.impact,
    residualAssessed: risk.residual !== null,
    residualLikelihood: risk.residual?.likelihood ?? 3,
    residualImpact: risk.residual?.impact ?? 3,
    treatment: risk.treatment,
    acceptanceDate: toDateInput(risk.acceptanceExpiry),
    reviewCadenceDays: risk.reviewCadenceDays,
    lastReviewedDate: toDateInput(risk.lastReviewedAt),
    linkedIssueIds: risk.linkedIssueIds.join('\n'),
    linkedControls: risk.linkedControls.join(', '),
  };
}

function payloadFrom(form: FormState): Record<string, unknown> {
  return {
    title: form.title.trim(),
    description: form.description,
    category: form.category,
    owner: form.owner.trim(),
    status: form.status,
    inherent: { likelihood: form.likelihood, impact: form.impact },
    residual: form.residualAssessed
      ? { likelihood: form.residualLikelihood, impact: form.residualImpact }
      : null,
    treatment: form.treatment,
    acceptanceExpiry: fromDateInput(form.acceptanceDate),
    reviewCadenceDays: form.reviewCadenceDays,
    lastReviewedAt: fromDateInput(form.lastReviewedDate),
    linkedIssueIds: form.linkedIssueIds
      .split('\n')
      .map((line) => line.trim())
      .filter(Boolean),
    linkedControls: form.linkedControls
      .split(',')
      .map((entry) => entry.trim())
      .filter(Boolean),
  };
}

function isOverdue(nextReviewAt: string | null): boolean {
  return Boolean(nextReviewAt && Date.parse(nextReviewAt) < Date.now());
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <dt className="text-sm font-medium text-gray-500">{label}</dt>
      <dd className="mt-1 text-sm text-gray-900">{children}</dd>
    </div>
  );
}

function RatingField({
  label,
  value,
  onChange,
}: {
  label: string;
  value: number;
  onChange: (value: number) => void;
}) {
  return (
    <SelectField
      label={label}
      value={value}
      onChange={(event) => onChange(Number(event.target.value))}
    >
      {RATINGS.map((rating) => (
        <option key={rating} value={rating}>
          {rating}
        </option>
      ))}
    </SelectField>
  );
}

export default function RiskDetailPage() {
  const router = useRouter();
  const search = useSearchParams();
  const id = search.get('id') ?? '';
  const risk = useRequest((signal) => getRisk(id, { signal }), [id], { enabled: Boolean(id) });
  const session = useRequest((signal) => getSession({ signal }), []);
  const role = session.status === 'success' ? session.data.role : null;
  const canManage = role === 'Admin' || role === 'Analyst';

  const [editing, setEditing] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [form, setForm] = useState<FormState | null>(null);

  const save = useAsyncAction(async () => {
    if (risk.status !== 'success' || !form) return;
    await updateRisk(id, payloadFrom(form));
    setEditing(false);
    risk.reload();
  });
  const remove = useAsyncAction(async () => {
    await deleteRisk(id);
    router.push('/risks');
  });

  if (!id) {
    return (
      <>
        <PageHeader title="Risk" {...BACK} />
        <PageBody>
          <NotFoundState title="Risk" message="No risk id was given." {...BACK} />
        </PageBody>
      </>
    );
  }

  if (risk.status === 'error') {
    if (isNotFound(risk.error)) {
      return (
        <>
          <PageHeader title="Risk" {...BACK} />
          <PageBody>
            <NotFoundState title="Risk" message={`No risk with id ${id} exists.`} {...BACK} />
          </PageBody>
        </>
      );
    }
    return (
      <>
        <PageHeader title="Risk" {...BACK} />
        <PageBody>
          <ErrorState error={risk.error} onRetry={risk.reload} />
        </PageBody>
      </>
    );
  }

  if (risk.status !== 'success') {
    return (
      <>
        <PageHeader title="Risk" {...BACK} />
        <PageBody>
          <LoadingState label="Loading risk…" />
        </PageBody>
      </>
    );
  }

  const detail = risk.data;
  const set = (patch: Partial<FormState>) =>
    setForm((current) => (current ? { ...current, ...patch } : current));

  return (
    <>
      <PageHeader
        title={detail.title}
        description={`${detail.category} · owner ${detail.owner || '—'} · updated ${formatTimestamp(detail.updatedAt)} by ${detail.updatedBy || '—'}`}
        actions={
          canManage && !editing ? (
            <>
              <button
                type="button"
                className={SECONDARY_BUTTON}
                onClick={() => {
                  setForm(formFrom(detail));
                  setEditing(true);
                }}
              >
                Edit
              </button>
              {confirmDelete ? (
                <>
                  <button
                    type="button"
                    className={SECONDARY_BUTTON}
                    disabled={remove.pending}
                    onClick={() => void remove.run()}
                  >
                    {remove.pending && <Spinner />}
                    Really delete
                  </button>
                  <button
                    type="button"
                    className={SECONDARY_BUTTON}
                    onClick={() => setConfirmDelete(false)}
                  >
                    Cancel
                  </button>
                </>
              ) : (
                <button
                  type="button"
                  className={SECONDARY_BUTTON}
                  onClick={() => setConfirmDelete(true)}
                >
                  Delete
                </button>
              )}
            </>
          ) : undefined
        }
      />

      <PageBody>
        {remove.error !== undefined && <ErrorState error={remove.error} />}
        {editing && form ? (
          <Card title="Edit risk">
            <form
              className="space-y-5"
              noValidate
              onSubmit={(event) => {
                event.preventDefault();
                if (form.title.trim()) void save.run();
              }}
            >
              <TextField
                label="Title"
                maxLength={200}
                value={form.title}
                onChange={(event) => set({ title: event.target.value })}
              />
              <div>
                <label
                  className="block text-sm font-medium text-gray-700"
                  htmlFor="risk-description"
                >
                  Description
                </label>
                <textarea
                  id="risk-description"
                  rows={3}
                  maxLength={2000}
                  className={TEXTAREA}
                  value={form.description}
                  onChange={(event) => set({ description: event.target.value })}
                />
              </div>
              <div className="grid gap-4 sm:grid-cols-3">
                <SelectField
                  label="Category"
                  value={form.category}
                  onChange={(event) =>
                    set({ category: event.target.value as RiskRegisterEntry['category'] })
                  }
                >
                  <option value="security">security</option>
                  <option value="compliance">compliance</option>
                  <option value="privacy">privacy</option>
                  <option value="operational">operational</option>
                  <option value="ai">ai</option>
                </SelectField>
                <SelectField
                  label="Status"
                  value={form.status}
                  onChange={(event) =>
                    set({ status: event.target.value as RiskRegisterEntry['status'] })
                  }
                >
                  <option value="open">open</option>
                  <option value="monitoring">monitoring</option>
                  <option value="accepted">accepted</option>
                  <option value="closed">closed</option>
                </SelectField>
                <TextField
                  label="Owner"
                  maxLength={120}
                  value={form.owner}
                  onChange={(event) => set({ owner: event.target.value })}
                />
              </div>

              <fieldset className="space-y-4 border-t border-gray-200 pt-5">
                <legend className="text-sm font-semibold text-gray-900">Ratings</legend>
                <div className="grid gap-4 sm:grid-cols-2">
                  <RatingField
                    label="Inherent likelihood (1-5)"
                    value={form.likelihood}
                    onChange={(likelihood) => set({ likelihood })}
                  />
                  <RatingField
                    label="Inherent impact (1-5)"
                    value={form.impact}
                    onChange={(impact) => set({ impact })}
                  />
                </div>
                <label className="flex items-center gap-2 text-sm text-gray-700">
                  <input
                    type="checkbox"
                    checked={form.residualAssessed}
                    onChange={(event) => set({ residualAssessed: event.target.checked })}
                  />
                  Residual risk assessed
                </label>
                {form.residualAssessed && (
                  <div className="grid gap-4 sm:grid-cols-2">
                    <RatingField
                      label="Residual likelihood (1-5)"
                      value={form.residualLikelihood}
                      onChange={(residualLikelihood) => set({ residualLikelihood })}
                    />
                    <RatingField
                      label="Residual impact (1-5)"
                      value={form.residualImpact}
                      onChange={(residualImpact) => set({ residualImpact })}
                    />
                  </div>
                )}
              </fieldset>

              <fieldset className="space-y-4 border-t border-gray-200 pt-5">
                <legend className="text-sm font-semibold text-gray-900">
                  Treatment and review
                </legend>
                <div className="grid gap-4 sm:grid-cols-3">
                  <SelectField
                    label="Treatment"
                    value={form.treatment}
                    onChange={(event) =>
                      set({ treatment: event.target.value as RiskRegisterEntry['treatment'] })
                    }
                  >
                    <option value="mitigate">mitigate</option>
                    <option value="accept">accept</option>
                    <option value="transfer">transfer</option>
                    <option value="avoid">avoid</option>
                  </SelectField>
                  {form.treatment === 'accept' && (
                    <TextField
                      label="Acceptance expiry"
                      type="date"
                      value={form.acceptanceDate}
                      onChange={(event) => set({ acceptanceDate: event.target.value })}
                    />
                  )}
                  <TextField
                    label="Review cadence (days)"
                    type="number"
                    min={1}
                    max={365}
                    value={form.reviewCadenceDays}
                    onChange={(event) => set({ reviewCadenceDays: Number(event.target.value) })}
                  />
                  <TextField
                    label="Last reviewed"
                    type="date"
                    value={form.lastReviewedDate}
                    onChange={(event) => set({ lastReviewedDate: event.target.value })}
                  />
                </div>
              </fieldset>

              <fieldset className="space-y-4 border-t border-gray-200 pt-5">
                <legend className="text-sm font-semibold text-gray-900">Links</legend>
                <div>
                  <label className="block text-sm font-medium text-gray-700" htmlFor="risk-issues">
                    Linked issue ids (one per line)
                  </label>
                  <textarea
                    id="risk-issues"
                    rows={2}
                    className={TEXTAREA}
                    value={form.linkedIssueIds}
                    onChange={(event) => set({ linkedIssueIds: event.target.value })}
                  />
                </div>
                <TextField
                  label="Linked controls"
                  hint="Comma-separated canonical control ids, e.g. KH-IAM-1, CIS 1.5"
                  value={form.linkedControls}
                  onChange={(event) => set({ linkedControls: event.target.value })}
                />
              </fieldset>

              {save.error !== undefined && <ErrorState error={save.error} />}
              <div className="flex items-center gap-3">
                <button
                  type="submit"
                  className={PRIMARY_BUTTON}
                  disabled={
                    save.pending ||
                    !form.title.trim() ||
                    (form.treatment === 'accept' && !form.acceptanceDate)
                  }
                >
                  {save.pending && <Spinner />}
                  {save.pending ? 'Saving…' : 'Save changes'}
                </button>
                <button
                  type="button"
                  className={SECONDARY_BUTTON}
                  onClick={() => setEditing(false)}
                >
                  Cancel
                </button>
              </div>
            </form>
          </Card>
        ) : (
          <div className="space-y-6">
            <Card title="Risk">
              <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                <Field label="Category">{detail.category}</Field>
                <Field label="Status">
                  <Badge tone={STATUS_TONES[detail.status]}>{detail.status}</Badge>
                </Field>
                <Field label="Owner">{detail.owner || '—'}</Field>
                <Field label="Treatment">{detail.treatment}</Field>
                {detail.treatment === 'accept' && (
                  <Field label="Acceptance expiry">
                    {detail.acceptanceExpiry ? formatTimestamp(detail.acceptanceExpiry) : '—'}
                  </Field>
                )}
                <Field label="Review cadence">every {detail.reviewCadenceDays} days</Field>
                <Field label="Last reviewed">
                  {detail.lastReviewedAt ? formatTimestamp(detail.lastReviewedAt) : 'never'}
                </Field>
                <Field label="Next review">
                  <span
                    className={isOverdue(detail.nextReviewAt) ? 'font-medium text-red-700' : ''}
                  >
                    {detail.nextReviewAt ? formatTimestamp(detail.nextReviewAt) : '—'}
                    {isOverdue(detail.nextReviewAt) && ' — overdue'}
                  </span>
                </Field>
              </div>
              {detail.description && (
                <p className="mt-4 text-sm text-gray-700">{detail.description}</p>
              )}
            </Card>

            <Card title="Ratings">
              <div className="grid gap-4 sm:grid-cols-2">
                <Field label="Inherent">
                  <span className="inline-flex items-center gap-2">
                    <RiskBadge level={detail.inherentLevel} />
                    <span className="text-gray-600">
                      L{detail.inherent.likelihood} × I{detail.inherent.impact} ={' '}
                      {detail.inherentScore}
                    </span>
                  </span>
                </Field>
                <Field label="Residual">
                  {detail.residual === null ? (
                    <span className="text-gray-500">Not assessed</span>
                  ) : (
                    <span className="inline-flex items-center gap-2">
                      <RiskBadge level={detail.residualLevel ?? 'low'} />
                      <span className="text-gray-600">
                        L{detail.residual.likelihood} × I{detail.residual.impact} ={' '}
                        {detail.residualScore}
                      </span>
                    </span>
                  )}
                </Field>
              </div>
            </Card>

            <Card title="Links">
              <div className="space-y-4">
                <Field label={`Linked issues (${detail.linkedIssueIds.length})`}>
                  {detail.linkedIssueIds.length === 0 ? (
                    <span className="text-gray-500">None.</span>
                  ) : (
                    <ul className="space-y-0.5">
                      {detail.linkedIssueIds.map((issueId) => (
                        <li key={issueId}>
                          <Link href={`/issues/${encodeURIComponent(issueId)}`} className={LINK}>
                            {issueId}
                          </Link>
                        </li>
                      ))}
                    </ul>
                  )}
                </Field>
                <Field label={`Linked controls (${detail.linkedControls.length})`}>
                  {detail.linkedControls.length === 0 ? (
                    <span className="text-gray-500">None.</span>
                  ) : (
                    <span className="flex flex-wrap gap-2">
                      {detail.linkedControls.map((control) => (
                        <Badge key={control} tone={TONES.neutral}>
                          {control}
                        </Badge>
                      ))}
                    </span>
                  )}
                </Field>
              </div>
            </Card>
          </div>
        )}
      </PageBody>
    </>
  );
}

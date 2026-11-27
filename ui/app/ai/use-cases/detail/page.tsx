'use client';

import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { useState, type ReactNode } from 'react';
import {
  deleteAiUseCase,
  formatTimestamp,
  getAiUseCase,
  getSession,
  isNotFound,
  updateAiUseCase,
} from '@/lib/api';
import { resourceHref } from '@/lib/routes';
import { useAsyncAction, useRequest } from '@/lib/use-request';
import type { AiAssessment, AiUseCase } from '@/types';
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

const BACK = { backHref: '/ai/use-cases', backLabel: '← Back to AI use cases' };
const TEXTAREA =
  'mt-1 block w-full resize-y rounded-md border border-gray-300 bg-white px-2.5 py-1.5 text-sm text-gray-900 shadow-xs focus:border-indigo-500 focus:outline-hidden focus:ring-2 focus:ring-indigo-500/20';

const STATUS_TONES: Record<AiUseCase['status'], string> = {
  draft: TONES.neutral,
  approved: TONES.success,
  retired: TONES.muted,
};
const ASSESSMENT_TONES: Record<AiAssessment['status'], string> = {
  draft: TONES.neutral,
  approved: TONES.success,
  rejected: TONES.danger,
};

interface FormState {
  name: string;
  owner: string;
  status: AiUseCase['status'];
  description: string;
  assets: string;
  dataClasses: string;
  assessment: {
    status: AiAssessment['status'];
    riskTier: AiAssessment['riskTier'];
    owner: string;
    humanOversight: string;
    impacts: string;
    notes: string;
  };
}

function formFrom(useCase: AiUseCase): FormState {
  return {
    name: useCase.name,
    owner: useCase.owner,
    status: useCase.status,
    description: useCase.description,
    assets: useCase.assets.join('\n'),
    dataClasses: useCase.dataClasses.join(', '),
    assessment: {
      status: useCase.assessment?.status ?? 'draft',
      riskTier: useCase.assessment?.riskTier ?? 'low',
      owner: useCase.assessment?.owner ?? '',
      humanOversight: useCase.assessment?.humanOversight ?? '',
      impacts: useCase.assessment?.impacts ?? '',
      notes: useCase.assessment?.notes ?? '',
    },
  };
}

// The assessment is sent as null when the record never had one and nothing in
// the form says otherwise, so saving an unrelated edit does not silently
// create a draft assessment.
function payloadFrom(form: FormState, original: AiUseCase): Record<string, unknown> {
  const touched =
    form.assessment.status !== 'draft' ||
    form.assessment.riskTier !== 'low' ||
    Boolean(
      form.assessment.owner ||
      form.assessment.humanOversight ||
      form.assessment.impacts ||
      form.assessment.notes
    );
  return {
    name: form.name.trim(),
    owner: form.owner.trim(),
    status: form.status,
    description: form.description,
    assets: form.assets
      .split('\n')
      .map((line) => line.trim())
      .filter(Boolean),
    dataClasses: form.dataClasses
      .split(',')
      .map((entry) => entry.trim())
      .filter(Boolean),
    assessment:
      original.assessment || touched
        ? {
            status: form.assessment.status,
            riskTier: form.assessment.riskTier,
            owner: form.assessment.owner,
            humanOversight: form.assessment.humanOversight,
            impacts: form.assessment.impacts,
            notes: form.assessment.notes,
          }
        : null,
  };
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <dt className="text-sm font-medium text-gray-500">{label}</dt>
      <dd className="mt-1 text-sm text-gray-900">{children}</dd>
    </div>
  );
}

export default function AiUseCaseDetailPage() {
  const router = useRouter();
  const search = useSearchParams();
  const id = search.get('id') ?? '';
  const useCase = useRequest((signal) => getAiUseCase(id, { signal }), [id], {
    enabled: Boolean(id),
  });
  const session = useRequest((signal) => getSession({ signal }), []);
  const role = session.status === 'success' ? session.data.role : null;
  const canManage = role === 'Admin' || role === 'Analyst';

  const [editing, setEditing] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [form, setForm] = useState<FormState | null>(null);

  const save = useAsyncAction(async () => {
    if (useCase.status !== 'success' || !form) return;
    await updateAiUseCase(id, payloadFrom(form, useCase.data));
    setEditing(false);
    useCase.reload();
  });
  const remove = useAsyncAction(async () => {
    await deleteAiUseCase(id);
    router.push('/ai/use-cases');
  });

  if (!id) {
    return (
      <>
        <PageHeader title="AI use case" {...BACK} />
        <PageBody>
          <NotFoundState title="AI use case" message="No use case id was given." {...BACK} />
        </PageBody>
      </>
    );
  }

  if (useCase.status === 'error') {
    if (isNotFound(useCase.error)) {
      return (
        <>
          <PageHeader title="AI use case" {...BACK} />
          <PageBody>
            <NotFoundState
              title="AI use case"
              message={`No use case with id ${id} exists.`}
              {...BACK}
            />
          </PageBody>
        </>
      );
    }
    return (
      <>
        <PageHeader title="AI use case" {...BACK} />
        <PageBody>
          <ErrorState error={useCase.error} onRetry={useCase.reload} />
        </PageBody>
      </>
    );
  }

  if (useCase.status !== 'success') {
    return (
      <>
        <PageHeader title="AI use case" {...BACK} />
        <PageBody>
          <LoadingState label="Loading use case…" />
        </PageBody>
      </>
    );
  }

  const detail = useCase.data;
  const set = (patch: Partial<FormState>) =>
    setForm((current) => (current ? { ...current, ...patch } : current));
  const setAssessment = (patch: Partial<FormState['assessment']>) =>
    setForm((current) =>
      current ? { ...current, assessment: { ...current.assessment, ...patch } } : current
    );

  return (
    <>
      <PageHeader
        title={detail.name}
        description={`Owner ${detail.owner || '—'} · updated ${formatTimestamp(detail.updatedAt)} by ${detail.updatedBy || '—'}`}
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
          <Card title="Edit use case">
            <form
              className="space-y-5"
              noValidate
              onSubmit={(event) => {
                event.preventDefault();
                if (form.name.trim()) void save.run();
              }}
            >
              <div className="grid gap-4 sm:grid-cols-2">
                <TextField
                  label="Name"
                  maxLength={200}
                  value={form.name}
                  onChange={(event) => set({ name: event.target.value })}
                />
                <TextField
                  label="Owner"
                  maxLength={120}
                  value={form.owner}
                  onChange={(event) => set({ owner: event.target.value })}
                />
              </div>
              <SelectField
                label="Status"
                value={form.status}
                onChange={(event) => set({ status: event.target.value as AiUseCase['status'] })}
              >
                <option value="draft">draft</option>
                <option value="approved">approved</option>
                <option value="retired">retired</option>
              </SelectField>
              <div>
                <label
                  className="block text-sm font-medium text-gray-700"
                  htmlFor="use-case-description"
                >
                  Description
                </label>
                <textarea
                  id="use-case-description"
                  rows={3}
                  maxLength={2000}
                  className={TEXTAREA}
                  value={form.description}
                  onChange={(event) => set({ description: event.target.value })}
                />
              </div>
              <div>
                <label
                  className="block text-sm font-medium text-gray-700"
                  htmlFor="use-case-assets"
                >
                  Covered asset ARNs (one per line, up to 50)
                </label>
                <textarea
                  id="use-case-assets"
                  rows={4}
                  className={TEXTAREA}
                  value={form.assets}
                  onChange={(event) => set({ assets: event.target.value })}
                />
              </div>
              <TextField
                label="Data classes"
                hint="Comma-separated, e.g. internal, customer-pii"
                value={form.dataClasses}
                onChange={(event) => set({ dataClasses: event.target.value })}
              />

              <fieldset className="space-y-4 border-t border-gray-200 pt-5">
                <legend className="text-sm font-semibold text-gray-900">
                  Lite impact assessment
                </legend>
                <div className="grid gap-4 sm:grid-cols-3">
                  <SelectField
                    label="Assessment status"
                    value={form.assessment.status}
                    onChange={(event) =>
                      setAssessment({ status: event.target.value as AiAssessment['status'] })
                    }
                  >
                    <option value="draft">draft</option>
                    <option value="approved">approved</option>
                    <option value="rejected">rejected</option>
                  </SelectField>
                  <SelectField
                    label="Risk tier"
                    value={form.assessment.riskTier}
                    onChange={(event) =>
                      setAssessment({ riskTier: event.target.value as AiAssessment['riskTier'] })
                    }
                  >
                    <option value="low">low</option>
                    <option value="medium">medium</option>
                    <option value="high">high</option>
                  </SelectField>
                  <TextField
                    label="Assessment owner"
                    maxLength={120}
                    value={form.assessment.owner}
                    onChange={(event) => setAssessment({ owner: event.target.value })}
                  />
                </div>
                <div>
                  <label
                    className="block text-sm font-medium text-gray-700"
                    htmlFor="use-case-oversight"
                  >
                    Human oversight
                  </label>
                  <textarea
                    id="use-case-oversight"
                    rows={2}
                    maxLength={1000}
                    className={TEXTAREA}
                    value={form.assessment.humanOversight}
                    onChange={(event) => setAssessment({ humanOversight: event.target.value })}
                  />
                </div>
                <div>
                  <label
                    className="block text-sm font-medium text-gray-700"
                    htmlFor="use-case-notes"
                  >
                    Notes
                  </label>
                  <textarea
                    id="use-case-notes"
                    rows={2}
                    maxLength={2000}
                    className={TEXTAREA}
                    value={form.assessment.notes}
                    onChange={(event) => setAssessment({ notes: event.target.value })}
                  />
                </div>
              </fieldset>

              {save.error !== undefined && <ErrorState error={save.error} />}
              <div className="flex items-center gap-3">
                <button
                  type="submit"
                  className={PRIMARY_BUTTON}
                  disabled={save.pending || !form.name.trim()}
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
            <Card title="Use case">
              <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                <Field label="Status">
                  <Badge tone={STATUS_TONES[detail.status]}>{detail.status}</Badge>
                </Field>
                <Field label="Owner">{detail.owner || '—'}</Field>
                <Field label="Assets">{detail.assets.length}</Field>
                <Field label="Data classes">
                  {detail.dataClasses.length > 0 ? detail.dataClasses.join(', ') : '—'}
                </Field>
              </div>
              {detail.description && (
                <p className="mt-4 text-sm text-gray-700">{detail.description}</p>
              )}
            </Card>

            {detail.assets.length > 0 && (
              <Card title={`Covered assets (${detail.assets.length})`} flush>
                <ul className="divide-y divide-gray-200">
                  {detail.assets.map((asset) => (
                    <li key={asset} className="px-6 py-2">
                      <Link href={resourceHref(asset)} className={LINK}>
                        {asset}
                      </Link>
                    </li>
                  ))}
                </ul>
              </Card>
            )}

            <Card title="Lite impact assessment">
              {!detail.assessment ? (
                <p className="text-sm text-gray-600">
                  No assessment recorded. {canManage ? 'Edit to add one.' : ''}
                </p>
              ) : (
                <div className="space-y-4">
                  <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                    <Field label="Status">
                      <Badge tone={ASSESSMENT_TONES[detail.assessment.status]}>
                        {detail.assessment.status}
                      </Badge>
                    </Field>
                    <Field label="Risk tier">
                      <RiskBadge level={detail.assessment.riskTier} />
                    </Field>
                    <Field label="Assessment owner">{detail.assessment.owner || '—'}</Field>
                    <Field label="Updated">
                      {formatTimestamp(detail.assessment.updatedAt)} by{' '}
                      {detail.assessment.updatedBy || '—'}
                    </Field>
                  </div>
                  <Field label="Human oversight">{detail.assessment.humanOversight || '—'}</Field>
                  {detail.assessment.impacts && (
                    <Field label="Impacts">{detail.assessment.impacts}</Field>
                  )}
                  {detail.assessment.notes && (
                    <Field label="Notes">{detail.assessment.notes}</Field>
                  )}
                </div>
              )}
            </Card>
          </div>
        )}
      </PageBody>
    </>
  );
}

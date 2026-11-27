'use client';

import { useRouter, useSearchParams } from 'next/navigation';
import { useState, type ReactNode } from 'react';
import {
  deleteVendor,
  formatTimestamp,
  getSession,
  getVendor,
  isNotFound,
  updateVendor,
} from '@/lib/api';
import { useAsyncAction, useRequest } from '@/lib/use-request';
import type { VendorRegisterEntry } from '@/types';
import { ErrorState, LoadingState, NotFoundState } from '@/components/states';
import {
  Badge,
  Card,
  LINK,
  PageBody,
  PageHeader,
  PRIMARY_BUTTON,
  SECONDARY_BUTTON,
  SelectField,
  Spinner,
  TextField,
  TONES,
} from '@/components/ui';

const BACK = { backHref: '/vendors', backLabel: '← Back to the vendor register' };

const STATUS_TONES: Record<VendorRegisterEntry['status'], string> = {
  active: TONES.success,
  'under-review': TONES.warning,
  terminated: TONES.neutral,
};

const toDateInput = (iso: string | null): string => (iso ? iso.slice(0, 10) : '');
const fromDateInput = (value: string): string | null =>
  value ? new Date(`${value}T00:00:00.000Z`).toISOString() : null;

interface FormState {
  name: string;
  category: VendorRegisterEntry['category'];
  status: VendorRegisterEntry['status'];
  owner: string;
  purpose: string;
  location: string;
  dpaUrl: string;
  dataClasses: string;
  subprocessor: boolean;
  renewalDate: string;
  reviewCadenceDays: number;
  lastReviewedDate: string;
}

function formFrom(vendor: VendorRegisterEntry): FormState {
  return {
    name: vendor.name,
    category: vendor.category,
    status: vendor.status,
    owner: vendor.owner,
    purpose: vendor.purpose,
    location: vendor.location,
    dpaUrl: vendor.dpaUrl ?? '',
    dataClasses: vendor.dataClasses.join(', '),
    subprocessor: vendor.subprocessor,
    renewalDate: toDateInput(vendor.renewalAt),
    reviewCadenceDays: vendor.reviewCadenceDays,
    lastReviewedDate: toDateInput(vendor.lastReviewedAt),
  };
}

function payloadFrom(form: FormState): Record<string, unknown> {
  return {
    name: form.name.trim(),
    category: form.category,
    status: form.status,
    owner: form.owner.trim(),
    purpose: form.purpose,
    location: form.location,
    dpaUrl: form.dpaUrl.trim() || null,
    dataClasses: form.dataClasses
      .split(',')
      .map((entry) => entry.trim())
      .filter(Boolean),
    subprocessor: form.subprocessor,
    renewalAt: fromDateInput(form.renewalDate),
    reviewCadenceDays: form.reviewCadenceDays,
    lastReviewedAt: fromDateInput(form.lastReviewedDate),
  };
}

function isPast(at: string | null): boolean {
  return Boolean(at && Date.parse(at) < Date.now());
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <dt className="text-sm font-medium text-gray-500">{label}</dt>
      <dd className="mt-1 text-sm text-gray-900">{children}</dd>
    </div>
  );
}

export default function VendorDetailPage() {
  const router = useRouter();
  const search = useSearchParams();
  const id = search.get('id') ?? '';
  const vendor = useRequest((signal) => getVendor(id, { signal }), [id], {
    enabled: Boolean(id),
  });
  const session = useRequest((signal) => getSession({ signal }), []);
  const role = session.status === 'success' ? session.data.role : null;
  const canManage = role === 'Admin' || role === 'Analyst';

  const [editing, setEditing] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [form, setForm] = useState<FormState | null>(null);

  const save = useAsyncAction(async () => {
    if (vendor.status !== 'success' || !form) return;
    await updateVendor(id, payloadFrom(form));
    setEditing(false);
    vendor.reload();
  });
  const remove = useAsyncAction(async () => {
    await deleteVendor(id);
    router.push('/vendors');
  });

  if (!id) {
    return (
      <>
        <PageHeader title="Vendor" {...BACK} />
        <PageBody>
          <NotFoundState title="Vendor" message="No vendor id was given." {...BACK} />
        </PageBody>
      </>
    );
  }

  if (vendor.status === 'error') {
    if (isNotFound(vendor.error)) {
      return (
        <>
          <PageHeader title="Vendor" {...BACK} />
          <PageBody>
            <NotFoundState title="Vendor" message={`No vendor with id ${id} exists.`} {...BACK} />
          </PageBody>
        </>
      );
    }
    return (
      <>
        <PageHeader title="Vendor" {...BACK} />
        <PageBody>
          <ErrorState error={vendor.error} onRetry={vendor.reload} />
        </PageBody>
      </>
    );
  }

  if (vendor.status !== 'success') {
    return (
      <>
        <PageHeader title="Vendor" {...BACK} />
        <PageBody>
          <LoadingState label="Loading vendor…" />
        </PageBody>
      </>
    );
  }

  const detail = vendor.data;
  const set = (patch: Partial<FormState>) =>
    setForm((current) => (current ? { ...current, ...patch } : current));
  const subprocessorIncomplete = Boolean(
    form && form.subprocessor && (!form.purpose.trim() || !form.location.trim())
  );

  return (
    <>
      <PageHeader
        title={detail.name}
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
          <Card title="Edit vendor">
            <form
              className="space-y-5"
              noValidate
              onSubmit={(event) => {
                event.preventDefault();
                if (form.name.trim() && !subprocessorIncomplete) void save.run();
              }}
            >
              <div className="grid gap-4 sm:grid-cols-3">
                <TextField
                  label="Name"
                  maxLength={200}
                  value={form.name}
                  onChange={(event) => set({ name: event.target.value })}
                />
                <SelectField
                  label="Category"
                  value={form.category}
                  onChange={(event) =>
                    set({ category: event.target.value as VendorRegisterEntry['category'] })
                  }
                >
                  <option value="cloud">cloud</option>
                  <option value="ai">ai</option>
                  <option value="security">security</option>
                  <option value="saas">saas</option>
                  <option value="infrastructure">infrastructure</option>
                  <option value="other">other</option>
                </SelectField>
                <SelectField
                  label="Status"
                  value={form.status}
                  onChange={(event) =>
                    set({ status: event.target.value as VendorRegisterEntry['status'] })
                  }
                >
                  <option value="active">active</option>
                  <option value="under-review">under-review</option>
                  <option value="terminated">terminated</option>
                </SelectField>
              </div>
              <TextField
                label="Owner"
                maxLength={120}
                value={form.owner}
                onChange={(event) => set({ owner: event.target.value })}
              />

              <div className="grid gap-4 sm:grid-cols-2">
                <TextField
                  label="Purpose"
                  maxLength={200}
                  hint="What this vendor processes for the deployment."
                  value={form.purpose}
                  onChange={(event) => set({ purpose: event.target.value })}
                />
                <TextField
                  label="Location"
                  maxLength={120}
                  hint="Where the data is processed, e.g. us-east-1 or EU."
                  value={form.location}
                  onChange={(event) => set({ location: event.target.value })}
                />
              </div>
              <TextField
                label="DPA URL"
                type="url"
                maxLength={512}
                hint="Must be https."
                placeholder="https://example.com/dpa"
                value={form.dpaUrl}
                onChange={(event) => set({ dpaUrl: event.target.value })}
              />
              <TextField
                label="Data classes"
                hint="Comma-separated, e.g. internal, customer-pii"
                value={form.dataClasses}
                onChange={(event) => set({ dataClasses: event.target.value })}
              />

              <label className="flex items-center gap-2 text-sm text-gray-700">
                <input
                  type="checkbox"
                  checked={form.subprocessor}
                  onChange={(event) => set({ subprocessor: event.target.checked })}
                />
                Listed as a subprocessor on the trust center
              </label>
              {subprocessorIncomplete && (
                <p className="text-sm text-red-700">
                  A subprocessor listing requires its purpose and location.
                </p>
              )}

              <fieldset className="space-y-4 border-t border-gray-200 pt-5">
                <legend className="text-sm font-semibold text-gray-900">Renewal and review</legend>
                <div className="grid gap-4 sm:grid-cols-3">
                  <TextField
                    label="Renewal date"
                    type="date"
                    value={form.renewalDate}
                    onChange={(event) => set({ renewalDate: event.target.value })}
                  />
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

              {save.error !== undefined && <ErrorState error={save.error} />}
              <div className="flex items-center gap-3">
                <button
                  type="submit"
                  className={PRIMARY_BUTTON}
                  disabled={save.pending || !form.name.trim() || subprocessorIncomplete}
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
            <Card title="Vendor">
              <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                <Field label="Category">{detail.category}</Field>
                <Field label="Status">
                  <Badge tone={STATUS_TONES[detail.status]}>{detail.status}</Badge>
                </Field>
                <Field label="Subprocessor">
                  {detail.subprocessor ? (
                    <Badge tone={TONES.accent}>yes</Badge>
                  ) : (
                    <span className="text-gray-500">no</span>
                  )}
                </Field>
                <Field label="Owner">{detail.owner || '—'}</Field>
                <Field label="Purpose">{detail.purpose || '—'}</Field>
                <Field label="Location">{detail.location || '—'}</Field>
                <Field label="DPA">
                  {detail.dpaUrl ? (
                    <a
                      href={detail.dpaUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className={LINK}
                    >
                      {detail.dpaUrl}
                    </a>
                  ) : (
                    <span className="text-gray-500">Not recorded</span>
                  )}
                </Field>
                <Field label="Data classes">
                  {detail.dataClasses.length > 0 ? detail.dataClasses.join(', ') : '—'}
                </Field>
              </div>
            </Card>

            <Card title="Renewal and review">
              <div className="grid gap-4 sm:grid-cols-3">
                <Field label="Renewal date">
                  <span className={isPast(detail.renewalAt) ? 'font-medium text-red-700' : ''}>
                    {detail.renewalAt ? formatTimestamp(detail.renewalAt) : '—'}
                    {isPast(detail.renewalAt) && ' — passed'}
                  </span>
                </Field>
                <Field label="Review cadence">every {detail.reviewCadenceDays} days</Field>
                <Field label="Last reviewed">
                  {detail.lastReviewedAt ? formatTimestamp(detail.lastReviewedAt) : 'never'}
                </Field>
                <Field label="Next review">
                  <span className={isPast(detail.nextReviewAt) ? 'font-medium text-red-700' : ''}>
                    {detail.nextReviewAt ? formatTimestamp(detail.nextReviewAt) : '—'}
                    {isPast(detail.nextReviewAt) && ' — overdue'}
                  </span>
                </Field>
              </div>
            </Card>
          </div>
        )}
      </PageBody>
    </>
  );
}

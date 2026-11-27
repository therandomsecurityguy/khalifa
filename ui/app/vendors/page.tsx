'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useState } from 'react';
import { createVendor, formatTimestamp, getSession, getVendors } from '@/lib/api';
import { vendorHref } from '@/lib/routes';
import { useAsyncAction, useRequest } from '@/lib/use-request';
import type { VendorRegisterEntry } from '@/types';
import { EmptyState, ErrorState, LoadingState } from '@/components/states';
import {
  Badge,
  Card,
  LINK,
  PageBody,
  PageHeader,
  PRIMARY_BUTTON,
  SelectField,
  Spinner,
  Table,
  Td,
  TextField,
  Th,
  TONES,
} from '@/components/ui';

const STATUS_TONES: Record<VendorRegisterEntry['status'], string> = {
  active: TONES.success,
  'under-review': TONES.warning,
  terminated: TONES.neutral,
};

function isPast(at: string | null): boolean {
  return Boolean(at && Date.parse(at) < Date.now());
}

function CreateForm({ onCreated }: { onCreated: (id: string) => void }) {
  const [name, setName] = useState('');
  const [category, setCategory] = useState<VendorRegisterEntry['category']>('other');
  const create = useAsyncAction(async () => {
    const created = await createVendor({ name: name.trim(), category });
    onCreated(created.id);
  });

  return (
    <Card
      title="Register a vendor"
      description="Name and category only; DPA, subprocessor disclosure fields, renewal, and review cadence are filled in on the detail page."
    >
      <form
        className="space-y-4"
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          if (name.trim()) void create.run();
        }}
      >
        <div className="grid gap-4 sm:grid-cols-2">
          <TextField
            label="Name"
            maxLength={200}
            placeholder="Example Cloud"
            value={name}
            onChange={(event) => setName(event.target.value)}
          />
          <SelectField
            label="Category"
            value={category}
            onChange={(event) => setCategory(event.target.value as VendorRegisterEntry['category'])}
          >
            <option value="cloud">cloud</option>
            <option value="ai">ai</option>
            <option value="security">security</option>
            <option value="saas">saas</option>
            <option value="infrastructure">infrastructure</option>
            <option value="other">other</option>
          </SelectField>
        </div>
        {create.error !== undefined && <ErrorState error={create.error} />}
        <button type="submit" className={PRIMARY_BUTTON} disabled={create.pending || !name.trim()}>
          {create.pending && <Spinner />}
          {create.pending ? 'Creating…' : 'Create vendor'}
        </button>
      </form>
    </Card>
  );
}

export default function VendorRegisterPage() {
  const router = useRouter();
  const vendors = useRequest((signal) => getVendors({ signal }), []);
  const session = useRequest((signal) => getSession({ signal }), []);

  const role = session.status === 'success' ? session.data.role : null;
  const canManage = role === 'Admin' || role === 'Analyst';
  const items = vendors.status === 'success' ? vendors.data.items : [];

  return (
    <>
      <PageHeader
        title="Vendor register"
        description="Third-party relationships: categories, data classes, DPA links, subprocessor disclosure, renewal dates, and review cadence."
      />
      <PageBody>
        {vendors.status === 'error' ? (
          <ErrorState error={vendors.error} onRetry={vendors.reload} />
        ) : vendors.status !== 'success' ? (
          <LoadingState label="Loading vendor register…" />
        ) : (
          <div className="space-y-6">
            {canManage && <CreateForm onCreated={(id) => router.push(vendorHref(id))} />}

            <Card title={`Vendors (${items.length})`} flush>
              {items.length === 0 ? (
                <EmptyState
                  title="No vendors registered"
                  description="Register the first one above; subprocessor disclosures for the trust center start with an honest list here."
                />
              ) : (
                <Table caption="Vendor register">
                  <thead>
                    <tr>
                      <Th>Vendor</Th>
                      <Th>Category</Th>
                      <Th>Status</Th>
                      <Th>Subprocessor</Th>
                      <Th>Owner</Th>
                      <Th>Renewal</Th>
                      <Th>Next review</Th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-200">
                    {items.map((vendor) => (
                      <tr key={vendor.id}>
                        <Td className="text-gray-900">
                          <Link href={vendorHref(vendor.id)} className={LINK}>
                            {vendor.name}
                          </Link>
                        </Td>
                        <Td className="text-gray-500">{vendor.category}</Td>
                        <Td>
                          <Badge tone={STATUS_TONES[vendor.status]}>{vendor.status}</Badge>
                        </Td>
                        <Td>
                          {vendor.subprocessor ? (
                            <Badge tone={TONES.accent}>yes</Badge>
                          ) : (
                            <span className="text-gray-400">—</span>
                          )}
                        </Td>
                        <Td className="text-gray-500">{vendor.owner || '—'}</Td>
                        <Td className={isPast(vendor.renewalAt) ? 'text-red-700' : 'text-gray-500'}>
                          {vendor.renewalAt ? formatTimestamp(vendor.renewalAt) : '—'}
                        </Td>
                        <Td
                          className={
                            isPast(vendor.nextReviewAt)
                              ? 'font-medium text-red-700'
                              : 'text-gray-500'
                          }
                        >
                          {vendor.nextReviewAt ? formatTimestamp(vendor.nextReviewAt) : '—'}
                          {isPast(vendor.nextReviewAt) && ' — overdue'}
                        </Td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              )}
              {vendors.data.truncated && (
                <p className="border-t border-gray-200 px-6 py-2 text-xs text-gray-500">
                  The register is bounded; more vendors exist than shown here.
                </p>
              )}
            </Card>
          </div>
        )}
      </PageBody>
    </>
  );
}

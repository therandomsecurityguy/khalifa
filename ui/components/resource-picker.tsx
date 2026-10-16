'use client';

import { useEffect, useId, useState } from 'react';
import type { GraphVertex } from '@/types';
import { searchResources } from '@/lib/api';
import { formatNodeLabel, nodeName } from '@/lib/graph-labels';
import { SelectField, TextField } from '@/components/ui';

export interface PickedResource {
  id: string;
  name: string;
}

const PICKER_TYPES = [
  'S3Bucket',
  'IamRole',
  'Ec2Instance',
  'Secret',
  'RdsInstance',
  'DynamoDBTable',
  'LambdaFunction',
  'EksCluster',
];

const PAGE = 200;

// Resource search matches a property exactly, so the picker lists a type and
// narrows by name on the client.
export function ResourcePicker({
  label,
  value,
  onChange,
  compact = false,
}: {
  label: string;
  value: PickedResource | null;
  onChange: (resource: PickedResource | null) => void;
  // Stacks the fields for narrow containers such as a filter rail.
  compact?: boolean;
}) {
  const id = useId();
  const [type, setType] = useState(PICKER_TYPES[0]);
  const [text, setText] = useState('');
  const [candidates, setCandidates] = useState<GraphVertex[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [truncated, setTruncated] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    setError(null);
    searchResources(type, undefined, undefined, PAGE, { signal: controller.signal })
      .then((result) => {
        setCandidates(result.resources);
        setTruncated(Boolean(result.nextToken));
      })
      .catch((failure: unknown) => {
        if (controller.signal.aborted) return;
        setCandidates([]);
        setError(failure instanceof Error ? failure.message : 'Could not load resources');
      });
    return () => controller.abort();
  }, [type]);

  const needle = text.trim().toLowerCase();
  const matches = needle
    ? candidates
        .filter((vertex) => `${nodeName(vertex)} ${vertex.id}`.toLowerCase().includes(needle))
        .slice(0, 8)
    : [];

  if (value) {
    return (
      <div className="rounded-md border border-indigo-200 bg-indigo-50 px-3 py-2 text-sm">
        <div className="text-xs font-medium text-gray-600">{label}</div>
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="truncate font-medium text-gray-900">{value.name}</div>
            <div className="truncate font-mono text-xs text-gray-500">{value.id}</div>
          </div>
          <button
            type="button"
            onClick={() => onChange(null)}
            className="shrink-0 text-xs font-medium text-indigo-600 hover:text-indigo-900"
          >
            Change
          </button>
        </div>
      </div>
    );
  }

  return (
    <fieldset className="rounded-md border border-gray-200 p-3">
      <legend className="px-1 text-xs font-medium text-gray-600">{label}</legend>
      <div
        className={compact ? 'grid gap-3' : 'grid gap-3 sm:grid-cols-[minmax(0,1fr)_minmax(0,2fr)]'}
      >
        <SelectField label="Type" value={type} onChange={(event) => setType(event.target.value)}>
          {PICKER_TYPES.map((option) => (
            <option key={option} value={option}>
              {formatNodeLabel(option)}
            </option>
          ))}
        </SelectField>
        <TextField
          label="Name"
          placeholder="Start typing a name or ARN"
          value={text}
          autoComplete="off"
          aria-controls={`${id}-matches`}
          onChange={(event) => setText(event.target.value)}
        />
      </div>
      {error && <p className="mt-2 text-xs text-red-700">{error}</p>}
      {needle && !error && (
        <ul
          id={`${id}-matches`}
          className="mt-2 divide-y divide-gray-100 rounded-md border border-gray-200"
        >
          {matches.length === 0 && (
            <li className="px-3 py-2 text-xs text-gray-500">
              No {formatNodeLabel(type).toLowerCase()} matches
              {truncated ? ` in the first ${PAGE} loaded` : ''}.
            </li>
          )}
          {matches.map((vertex) => (
            <li key={vertex.id}>
              <button
                type="button"
                onClick={() => onChange({ id: vertex.id, name: nodeName(vertex) })}
                className="block w-full px-3 py-1.5 text-left text-sm hover:bg-orange-50"
              >
                <span className="block truncate font-medium text-gray-900">{nodeName(vertex)}</span>
                <span className="block truncate font-mono text-xs text-gray-500">{vertex.id}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </fieldset>
  );
}

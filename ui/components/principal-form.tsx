'use client';

import type { ReactNode } from 'react';
import { PRIMARY_BUTTON, TextField } from '@/components/ui';

export function PrincipalForm({
  principal,
  onPrincipalChange,
  onSubmit,
  extra,
}: {
  principal: string;
  onPrincipalChange: (value: string) => void;
  onSubmit: () => void;
  extra?: ReactNode;
}) {
  return (
    <form
      className="mb-6 flex flex-wrap items-end gap-4 rounded-lg bg-white p-4 shadow"
      onSubmit={(event) => {
        event.preventDefault();
        onSubmit();
      }}
    >
      <TextField
        label="Principal ARN"
        className="min-w-80 flex-1"
        value={principal}
        onChange={(event) => onPrincipalChange(event.target.value)}
        required
      />
      {extra}
      <button type="submit" className={PRIMARY_BUTTON}>
        Load
      </button>
    </form>
  );
}

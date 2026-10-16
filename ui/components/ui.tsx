import { useId, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes } from 'react';
import Link from 'next/link';

const FORM_CONTROL =
  'mt-1 block w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-gray-900 shadow-sm sm:text-sm';

export const PRIMARY_BUTTON =
  'inline-flex items-center justify-center gap-2 rounded-md border border-transparent bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-60';

export const SECONDARY_BUTTON =
  'inline-flex items-center justify-center gap-2 rounded-md border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:cursor-not-allowed disabled:opacity-60';

export const LINK = 'font-medium text-indigo-600 hover:text-indigo-900';

// Every text-on-tint pairing the UI renders. ui.test.tsx checks each against
// WCAG AA, so add new pairings here rather than inline.
export const TONES = {
  severity: {
    critical: 'bg-red-700 text-white',
    high: 'bg-orange-500 text-orange-950',
    medium: 'bg-yellow-400 text-yellow-950',
    low: 'bg-blue-700 text-white',
    unknown: 'bg-gray-600 text-white',
  },
  severitySoft: {
    critical: 'bg-red-100 text-red-800',
    high: 'bg-orange-100 text-orange-800',
    medium: 'bg-yellow-100 text-yellow-800',
    low: 'bg-blue-100 text-blue-800',
    unknown: 'bg-gray-100 text-gray-800',
  },
  status: {
    PASS: 'bg-green-100 text-green-800',
    FAIL: 'bg-red-100 text-red-800',
    MANUAL: 'bg-yellow-100 text-yellow-800',
    NOT_EVALUATED: 'bg-gray-100 text-gray-800',
    NOT_APPLICABLE: 'bg-blue-100 text-blue-800',
    unknown: 'bg-gray-100 text-gray-800',
  },
  neutral: 'bg-gray-100 text-gray-800',
  accent: 'bg-indigo-50 text-indigo-700',
  success: 'bg-green-50 text-green-800',
  warning: 'bg-yellow-50 text-yellow-800',
  danger: 'bg-red-50 text-red-800',
  info: 'bg-blue-50 text-blue-800',
  navActive: 'bg-gray-900 text-white',
  navInactive: 'bg-sky-100 text-gray-700',
  primaryButton: 'bg-indigo-600 text-white',
  secondaryButton: 'bg-white text-gray-700',
  muted: 'bg-white text-gray-500',
  mutedOnPanel: 'bg-orange-50 text-gray-500',
  link: 'bg-white text-indigo-600',
} as const;

// Tinted summary tiles: the box tint with its value colour. Labels on every
// tile use text-gray-600, which the contrast test also checks against each box.
export const TILE_TONES = {
  neutral: { box: 'bg-white', value: 'text-gray-900' },
  success: { box: 'bg-green-50', value: 'text-green-700' },
  danger: { box: 'bg-red-50', value: 'text-red-700' },
  warning: { box: 'bg-yellow-50', value: 'text-yellow-800' },
  info: { box: 'bg-blue-50', value: 'text-blue-700' },
  accent: { box: 'bg-indigo-50', value: 'text-indigo-700' },
} as const;

export function SummaryTile({
  label,
  value,
  hint,
  tone = 'neutral',
}: {
  label: string;
  value: ReactNode;
  hint?: string;
  tone?: keyof typeof TILE_TONES;
}) {
  const palette = TILE_TONES[tone];
  return (
    <div className={`rounded-lg p-4 ${palette.box} ${tone === 'neutral' ? 'shadow' : ''}`}>
      <div className="text-sm font-medium text-gray-600">{label}</div>
      <div className={`mt-1 text-3xl font-bold ${palette.value}`}>{value}</div>
      {hint && <div className="mt-1 text-xs text-gray-600">{hint}</div>}
    </div>
  );
}

const RISK_TONES: Record<string, string> = {
  high: TONES.severity.critical,
  medium: TONES.severity.medium,
  low: TONES.severity.low,
};

const BADGE_SIZES = {
  sm: 'px-2.5 py-0.5 text-xs',
  md: 'px-3.5 py-1 text-sm',
} as const;

// A regional control's PASS covers only the regions that were collected.
export function RegionScopeBadge({ regions }: { regions?: string[] }) {
  if (!regions || regions.length === 0) return null;
  return (
    <span title={`Evaluated in ${regions.join(', ')} only; other regions were not collected`}>
      <Badge tone={TONES.warning}>
        {regions.length === 1 ? `${regions[0]} only` : `${regions.length} regions`}
      </Badge>
    </span>
  );
}

export function Badge({
  tone,
  size = 'sm',
  children,
}: {
  tone: string;
  size?: keyof typeof BADGE_SIZES;
  children: ReactNode;
}) {
  return (
    <span
      className={`inline-flex items-center rounded-full font-medium ${BADGE_SIZES[size]} ${tone}`}
    >
      {children}
    </span>
  );
}

export function SeverityBadge({
  severity,
  tone = 'solid',
  size,
}: {
  severity: string;
  tone?: 'solid' | 'soft';
  size?: keyof typeof BADGE_SIZES;
}) {
  const palette: Record<string, string> = tone === 'soft' ? TONES.severitySoft : TONES.severity;
  return (
    <Badge tone={palette[severity] ?? palette.unknown} size={size}>
      {severity}
    </Badge>
  );
}

export function StatusBadge({ status }: { status: string }) {
  const palette: Record<string, string> = TONES.status;
  return <Badge tone={palette[status] ?? palette.unknown}>{status}</Badge>;
}

const ISSUE_STATUS_TONES: Record<string, string> = {
  open: TONES.danger,
  resolved: TONES.success,
  suppressed: TONES.neutral,
};

export function IssueStatusBadge({ status }: { status: string }) {
  return <Badge tone={ISSUE_STATUS_TONES[status] ?? TONES.neutral}>{status}</Badge>;
}

export function RiskBadge({ level }: { level: string }) {
  return <Badge tone={RISK_TONES[level] ?? TONES.severity.unknown}>{level}</Badge>;
}

const STAT_BARS: Record<string, string> = {
  critical: 'border-l-4 border-red-700',
  high: 'border-l-4 border-orange-500',
  medium: 'border-l-4 border-yellow-400',
  low: 'border-l-4 border-blue-700',
};

export function StatCard({
  label,
  value,
  bar,
  hint,
}: {
  label: string;
  value: ReactNode;
  bar?: keyof typeof STAT_BARS;
  hint?: string;
}) {
  return (
    <div className={`rounded-lg bg-white p-6 shadow ${bar ? STAT_BARS[bar] : ''}`}>
      <div className="text-sm font-medium uppercase text-gray-500">{label}</div>
      <div className="mt-2 text-3xl font-semibold text-gray-900">{value}</div>
      {hint && <div className="mt-1 text-xs text-gray-500">{hint}</div>}
    </div>
  );
}

export function Card({
  title,
  description,
  actions,
  children,
  className = '',
  flush = false,
}: {
  title?: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  // Tables and filter bars manage their own edges; flush drops the body padding.
  flush?: boolean;
}) {
  return (
    <section className={`overflow-hidden rounded-lg bg-white shadow ${className}`}>
      {(title || actions) && (
        <div className="flex flex-wrap items-start justify-between gap-3 border-b border-sky-200 bg-sky-100 px-6 py-4">
          <div>
            {title && <h2 className="text-lg font-medium text-gray-900">{title}</h2>}
            {description && <p className="mt-1 text-sm text-gray-600">{description}</p>}
          </div>
          {actions && <div className="flex flex-wrap items-center gap-3">{actions}</div>}
        </div>
      )}
      <div className={flush ? '' : 'p-6'}>{children}</div>
    </section>
  );
}

export function PageHeader({
  title,
  description,
  backHref,
  backLabel,
  actions,
}: {
  title: string;
  description?: string;
  backHref?: string;
  backLabel?: string;
  actions?: ReactNode;
}) {
  return (
    <header className="border-b border-gray-200 bg-white">
      <div className="mx-auto flex max-w-7xl flex-col gap-4 px-4 py-6 sm:flex-row sm:items-center sm:justify-between sm:px-6 lg:px-8">
        <div>
          {backHref && (
            <Link href={backHref} className={`mb-2 inline-block text-sm ${LINK}`}>
              {backLabel ?? 'Back'}
            </Link>
          )}
          <h1 className="text-3xl font-bold text-gray-900">{title}</h1>
          {description && <p className="mt-2 text-gray-600">{description}</p>}
        </div>
        {actions && <div className="flex flex-wrap items-center gap-3">{actions}</div>}
      </div>
    </header>
  );
}

export function PageBody({ children }: { children: ReactNode }) {
  return <div className="mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8">{children}</div>;
}

export function Table({ children, caption }: { children: ReactNode; caption?: string }) {
  return (
    <div className="overflow-x-auto">
      <table className="min-w-full divide-y divide-gray-200">
        {caption && <caption className="sr-only">{caption}</caption>}
        {children}
      </table>
    </div>
  );
}

export function Th({ children, className = '' }: { children: ReactNode; className?: string }) {
  return (
    <th
      scope="col"
      className={`bg-orange-50 px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500 ${className}`}
    >
      {children}
    </th>
  );
}

export function Td({
  children,
  className = '',
  colSpan,
}: {
  children: ReactNode;
  className?: string;
  colSpan?: number;
}) {
  return (
    <td colSpan={colSpan} className={`px-6 py-4 text-sm text-gray-700 ${className}`}>
      {children}
    </td>
  );
}

type FieldProps = { label: string; hint?: string; className?: string };

export function TextField({
  label,
  hint,
  className = '',
  ...props
}: FieldProps & InputHTMLAttributes<HTMLInputElement>) {
  const id = useId();
  return (
    <div className={className}>
      <label htmlFor={id} className="block text-sm font-medium text-gray-700">
        {label}
      </label>
      <input
        id={id}
        className={FORM_CONTROL}
        aria-describedby={hint ? `${id}-hint` : undefined}
        {...props}
      />
      {hint && (
        <p id={`${id}-hint`} className="mt-1 text-xs text-gray-500">
          {hint}
        </p>
      )}
    </div>
  );
}

export function SelectField({
  label,
  hint,
  className = '',
  children,
  ...props
}: FieldProps & SelectHTMLAttributes<HTMLSelectElement>) {
  const id = useId();
  return (
    <div className={className}>
      <label htmlFor={id} className="block text-sm font-medium text-gray-700">
        {label}
      </label>
      <select
        id={id}
        className={FORM_CONTROL}
        aria-describedby={hint ? `${id}-hint` : undefined}
        {...props}
      >
        {children}
      </select>
      {hint && (
        <p id={`${id}-hint`} className="mt-1 text-xs text-gray-500">
          {hint}
        </p>
      )}
    </div>
  );
}

const MESSAGE_TONES = {
  info: `border-blue-200 ${TONES.info}`,
  success: `border-green-200 ${TONES.success}`,
  warning: `border-yellow-200 ${TONES.warning}`,
  error: `border-red-200 ${TONES.danger}`,
} as const;

// Feedback for something that just happened. Errors interrupt (role=alert);
// everything else is announced politely.
export function StatusMessage({
  tone,
  children,
  className = '',
}: {
  tone: keyof typeof MESSAGE_TONES;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div
      role={tone === 'error' ? 'alert' : 'status'}
      className={`rounded-md border p-4 text-sm ${MESSAGE_TONES[tone]} ${className}`}
    >
      {children}
    </div>
  );
}

export function Spinner({ className = 'h-4 w-4' }: { className?: string }) {
  return (
    <svg className={`animate-spin ${className}`} viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" className="opacity-25" />
      <path
        d="M4 12a8 8 0 018-8"
        stroke="currentColor"
        strokeWidth="4"
        strokeLinecap="round"
        className="opacity-75"
      />
    </svg>
  );
}

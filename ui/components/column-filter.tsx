'use client';

import { useEffect, useId, useRef, useState } from 'react';

export interface FilterOption {
  value: string;
  label: string;
  // How many rows the option would show, given the other filters.
  count?: number;
}

// A column-header funnel that opens a checklist; an empty selection means no filter.
export function ColumnFilter({
  label,
  options,
  selected,
  onChange,
}: {
  label: string;
  options: FilterOption[];
  selected: string[];
  onChange: (values: string[]) => void;
}) {
  const [position, setPosition] = useState<{ top: number; left: number } | null>(null);
  const open = position !== null;
  const root = useRef<HTMLDivElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const panelId = useId();
  const active = selected.length > 0;

  useEffect(() => {
    if (!open) return;
    const close = () => setPosition(null);
    const onPointer = (event: MouseEvent) => {
      if (!root.current?.contains(event.target as Node)) close();
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;
      close();
      trigger.current?.focus();
    };
    const onScroll = (event: Event) => {
      if (!root.current?.contains(event.target as Node)) close();
    };
    document.addEventListener('mousedown', onPointer);
    document.addEventListener('keydown', onKey);
    window.addEventListener('resize', close);
    window.addEventListener('scroll', onScroll, true);
    return () => {
      document.removeEventListener('mousedown', onPointer);
      document.removeEventListener('keydown', onKey);
      window.removeEventListener('resize', close);
      window.removeEventListener('scroll', onScroll, true);
    };
  }, [open]);

  // The panel is fixed to the viewport so the table's scroll container cannot clip it.
  function openPanel(): void {
    if (open) {
      setPosition(null);
      return;
    }
    const rect = trigger.current?.getBoundingClientRect();
    if (!rect) return;
    setPosition({ top: rect.bottom + 4, left: Math.min(rect.left, window.innerWidth - 232) });
  }

  function toggle(value: string): void {
    onChange(
      selected.includes(value) ? selected.filter((item) => item !== value) : [...selected, value]
    );
  }

  return (
    <div ref={root} className="inline-flex items-center gap-1">
      <span>{label}</span>
      <button
        ref={trigger}
        type="button"
        aria-label={`Filter ${label}`}
        aria-expanded={open}
        aria-controls={panelId}
        onClick={openPanel}
        className={`inline-flex items-center gap-0.5 rounded p-1 normal-case tracking-normal hover:bg-orange-100 ${
          active ? 'text-indigo-700' : 'text-gray-500'
        }`}
      >
        <svg
          className="h-3.5 w-3.5"
          viewBox="0 0 20 20"
          fill={active ? 'currentColor' : 'none'}
          stroke="currentColor"
          strokeWidth={1.6}
          aria-hidden="true"
        >
          <path strokeLinejoin="round" d="M3 4h14l-5.5 6.5V16l-3 1.5v-7L3 4z" />
        </svg>
        {active && <span className="text-xs font-semibold tabular-nums">{selected.length}</span>}
      </button>

      {position && (
        <div
          id={panelId}
          role="group"
          aria-label={`${label} filter`}
          style={{ top: position.top, left: Math.max(8, position.left) }}
          className="fixed z-30 w-56 rounded-md border border-gray-200 bg-white py-1 text-sm font-normal normal-case tracking-normal text-gray-900 shadow-lg"
        >
          <div className="max-h-64 overflow-y-auto">
            {options.length === 0 && <p className="px-3 py-2 text-gray-500">No values yet</p>}
            {options.map((option) => (
              <label
                key={option.value}
                className="flex cursor-pointer items-center gap-2 px-3 py-1.5 hover:bg-orange-50"
              >
                <input
                  type="checkbox"
                  className="h-4 w-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
                  checked={selected.includes(option.value)}
                  onChange={() => toggle(option.value)}
                />
                <span className="flex-1 truncate">{option.label}</span>
                {option.count !== undefined && (
                  <span className="text-xs tabular-nums text-gray-500">{option.count}</span>
                )}
              </label>
            ))}
          </div>
          <div className="mt-1 flex justify-end border-t border-gray-100 px-3 pt-1.5 pb-0.5">
            <button
              type="button"
              className="text-xs font-medium text-indigo-600 hover:text-indigo-900 disabled:text-gray-400"
              disabled={!active}
              onClick={() => onChange([])}
            >
              Clear
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

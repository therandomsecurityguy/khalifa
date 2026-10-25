'use client';

import { useEffect, useId, useRef, useState, type KeyboardEvent, type ReactNode } from 'react';

export interface SearchSelectOption {
  value: string;
  name: string;
  count?: number;
}

const ariaName = ({ name, count }: SearchSelectOption) =>
  count ? `${name} (${count.toLocaleString('en-US')})` : name;

function highlight(name: string, needle: string): ReactNode {
  const at = needle ? name.toLowerCase().indexOf(needle) : -1;
  if (at < 0) return name;
  return (
    <>
      {name.slice(0, at)}
      <mark className="bg-transparent font-semibold text-indigo-700">
        {name.slice(at, at + needle.length)}
      </mark>
      {name.slice(at + needle.length)}
    </>
  );
}

// A single-choice field you can type into to narrow a long list. Enter picks
// the highlighted option while the list is open, and submits the form when not.
export function SearchSelect({
  label,
  value,
  options,
  onChange,
  hint,
  placeholder = 'Type to search',
}: {
  label: string;
  value: string;
  options: SearchSelectOption[];
  onChange: (value: string) => void;
  hint?: string;
  placeholder?: string;
}) {
  const id = useId();
  const listRef = useRef<HTMLUListElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [active, setActive] = useState(0);

  const selected = options.find((option) => option.value === value);
  const needle = query.trim().toLowerCase();
  const matches = needle
    ? options.filter(
        (option) =>
          option.name.toLowerCase().includes(needle) || option.value.toLowerCase().includes(needle)
      )
    : options;

  useEffect(() => {
    if (!open) return;
    listRef.current
      ?.querySelector(`[data-index="${active}"]`)
      ?.scrollIntoView?.({ block: 'nearest' });
  }, [active, open]);

  function show(): void {
    setQuery('');
    setActive(Math.max(0, options.indexOf(selected as SearchSelectOption)));
    setOpen(true);
  }

  function close(): void {
    setOpen(false);
    setQuery('');
  }

  function pick(option: SearchSelectOption): void {
    onChange(option.value);
    close();
  }

  function onKeyDown(event: KeyboardEvent<HTMLInputElement>): void {
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault();
      if (!open) return show();
      const step = event.key === 'ArrowDown' ? 1 : -1;
      setActive((index) => Math.min(Math.max(index + step, 0), matches.length - 1));
    } else if (event.key === 'Enter' && open) {
      event.preventDefault();
      if (matches[active]) pick(matches[active]);
    } else if (event.key === 'Escape' && open) {
      event.preventDefault();
      close();
    }
  }

  const optionId = (index: number) => `${id}-option-${index}`;

  return (
    <div>
      <label htmlFor={id} className="block text-sm font-medium text-gray-700">
        {label}
      </label>
      <div className="relative mt-1">
        <svg
          aria-hidden="true"
          viewBox="0 0 20 20"
          fill="currentColor"
          className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-400"
        >
          <path
            fillRule="evenodd"
            d="M9 3.5a5.5 5.5 0 1 0 3.4 9.83l3.13 3.14a.75.75 0 1 0 1.06-1.06l-3.13-3.14A5.5 5.5 0 0 0 9 3.5ZM5 9a4 4 0 1 1 8 0 4 4 0 0 1-8 0Z"
            clipRule="evenodd"
          />
        </svg>
        <input
          ref={inputRef}
          id={id}
          type="text"
          role="combobox"
          autoComplete="off"
          spellCheck={false}
          aria-expanded={open}
          aria-controls={`${id}-list`}
          aria-autocomplete="list"
          aria-activedescendant={open && matches[active] ? optionId(active) : undefined}
          aria-describedby={hint ? `${id}-hint` : undefined}
          className="block w-full rounded-md border border-gray-300 bg-white py-2 pl-9 pr-9 text-gray-900 shadow-sm placeholder:text-gray-400 focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500 sm:text-sm"
          placeholder={open ? (selected?.name ?? placeholder) : placeholder}
          value={open ? query : (selected?.name ?? '')}
          onChange={(event) => {
            // Typed while closed, the keystroke lands after the chosen name;
            // keep only what was typed so it starts a new search.
            const typed = event.target.value;
            const shown = selected?.name ?? '';
            setQuery(!open && typed.startsWith(shown) ? typed.slice(shown.length) : typed);
            setActive(0);
            setOpen(true);
          }}
          onFocus={() => !open && show()}
          onClick={() => !open && show()}
          onKeyDown={onKeyDown}
          onBlur={close}
        />
        <button
          type="button"
          tabIndex={-1}
          aria-label={
            open ? `Close ${label.toLowerCase()} list` : `Show ${label.toLowerCase()} list`
          }
          className="absolute inset-y-0 right-0 flex items-center px-2.5 text-gray-400 hover:text-gray-600"
          onMouseDown={(event) => event.preventDefault()}
          onClick={() => {
            if (open) return close();
            inputRef.current?.focus();
            show();
          }}
        >
          <svg
            aria-hidden="true"
            viewBox="0 0 20 20"
            fill="currentColor"
            className={`h-4 w-4 transition-transform ${open ? 'rotate-180' : ''}`}
          >
            <path
              fillRule="evenodd"
              d="M5.22 8.22a.75.75 0 0 1 1.06 0L10 11.94l3.72-3.72a.75.75 0 1 1 1.06 1.06l-4.25 4.25a.75.75 0 0 1-1.06 0L5.22 9.28a.75.75 0 0 1 0-1.06Z"
              clipRule="evenodd"
            />
          </svg>
        </button>
        {open && (
          <ul
            ref={listRef}
            id={`${id}-list`}
            role="listbox"
            aria-label={label}
            className="absolute z-20 mt-1 max-h-72 w-full min-w-[20rem] overflow-auto rounded-md border border-gray-200 bg-white py-1 text-sm shadow-lg"
          >
            {matches.length === 0 && (
              <li className="px-3 py-2 text-gray-500">
                No {label.toLowerCase()}s match &ldquo;{query.trim()}&rdquo;
              </li>
            )}
            {matches.map((option, index) => {
              const isSelected = option.value === value;
              return (
                <li
                  key={option.value}
                  id={optionId(index)}
                  data-index={index}
                  role="option"
                  aria-selected={isSelected}
                  aria-label={ariaName(option)}
                  className={`flex cursor-pointer items-center gap-2 px-3 py-2 ${
                    index === active ? 'bg-indigo-50 text-indigo-900' : 'text-gray-900'
                  }`}
                  onMouseDown={(event) => event.preventDefault()}
                  onMouseEnter={() => setActive(index)}
                  onClick={() => pick(option)}
                >
                  <span className="flex w-4 shrink-0 justify-center text-indigo-600">
                    {isSelected && (
                      <svg
                        aria-hidden="true"
                        viewBox="0 0 20 20"
                        fill="currentColor"
                        className="h-4 w-4"
                      >
                        <path
                          fillRule="evenodd"
                          d="M16.7 5.3a1 1 0 0 1 0 1.4l-7.5 7.5a1 1 0 0 1-1.4 0l-3.5-3.5a1 1 0 1 1 1.4-1.4l2.8 2.79 6.8-6.8a1 1 0 0 1 1.4 0Z"
                          clipRule="evenodd"
                        />
                      </svg>
                    )}
                  </span>
                  <span className={`flex-1 truncate ${isSelected ? 'font-medium' : ''}`}>
                    {highlight(option.name, needle)}
                  </span>
                  {option.count ? (
                    <span className="shrink-0 tabular-nums text-xs text-gray-500">
                      {option.count.toLocaleString('en-US')}
                    </span>
                  ) : null}
                </li>
              );
            })}
          </ul>
        )}
      </div>
      {hint && (
        <p id={`${id}-hint`} className="mt-1 text-xs text-gray-500">
          {hint}
        </p>
      )}
    </div>
  );
}

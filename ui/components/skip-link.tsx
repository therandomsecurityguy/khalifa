'use client';

export const CONTENT_ID = 'content';

export function SkipLink() {
  return (
    <a
      href={`#${CONTENT_ID}`}
      onClick={() => document.getElementById(CONTENT_ID)?.focus()}
      className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-50 focus:rounded-md focus:bg-white focus:px-3 focus:py-2 focus:text-sm focus:font-medium focus:text-gray-900 focus:shadow"
    >
      Skip to content
    </a>
  );
}

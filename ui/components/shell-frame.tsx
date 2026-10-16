import type { ReactNode } from 'react';
import { AppNav } from './app-nav';
import { CONTENT_ID, SkipLink } from './skip-link';

export function ShellFrame({ children }: { children: ReactNode }) {
  return (
    <div className="min-h-screen bg-gray-50">
      <SkipLink />
      <AppNav />
      <main id={CONTENT_ID} tabIndex={-1} className="focus:outline-none">
        {children}
      </main>
    </div>
  );
}

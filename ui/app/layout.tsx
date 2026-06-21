import type { Metadata } from 'next';
import type { ReactNode } from 'react';
import ErrorBoundary from './error-boundary';

export const metadata: Metadata = {
  title: 'Khalifa - Security Graph',
  description: 'AWS security graph and risk engine',
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body className="antialiased">
        <ErrorBoundary>{children}</ErrorBoundary>
      </body>
    </html>
  );
}

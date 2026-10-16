import type { Metadata } from 'next';
import type { ReactNode } from 'react';
import { ShellFrame } from '@/components/shell-frame';
import './globals.css';

export const metadata: Metadata = {
  title: 'Khalifa - Security Graph',
  description: 'AWS security graph and risk engine',
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body className="antialiased">
        <ShellFrame>{children}</ShellFrame>
      </body>
    </html>
  );
}

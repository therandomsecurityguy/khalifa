import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Security Graph',
  description: 'Wiz-like internal security graph and risk engine',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="antialiased">{children}</body>
    </html>
  );
}

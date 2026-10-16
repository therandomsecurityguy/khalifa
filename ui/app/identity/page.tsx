import Link from 'next/link';
import { IDENTITY_ROUTES } from '@/lib/routes';
import { PageBody, PageHeader } from '@/components/ui';

export default function IdentityPage() {
  return (
    <>
      <PageHeader
        title="Identity"
        description="Effective permissions, trust, usage, and least-privilege recommendations."
      />
      <PageBody>
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          {IDENTITY_ROUTES.map((item) => (
            <Link
              key={item.href}
              href={item.href}
              className="rounded-lg bg-white p-6 shadow hover:bg-gray-50"
            >
              <h2 className="text-lg font-medium text-gray-900">{item.label}</h2>
              <p className="mt-2 text-sm text-gray-600">{item.description}</p>
            </Link>
          ))}
        </div>
      </PageBody>
    </>
  );
}

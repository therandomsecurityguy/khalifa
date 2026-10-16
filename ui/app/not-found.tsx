import Link from 'next/link';
import { LINK, PageBody, PageHeader } from '@/components/ui';

export default function NotFound() {
  return (
    <>
      <PageHeader title="Not found" description="That page does not exist." />
      <PageBody>
        <p className="text-gray-600">
          Check the address or return to{' '}
          <Link href="/issues" className={LINK}>
            Issues
          </Link>
          .
        </p>
      </PageBody>
    </>
  );
}

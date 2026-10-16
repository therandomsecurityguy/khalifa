import { LoadingState } from '@/components/states';
import { PageBody } from '@/components/ui';

export default function Loading() {
  return (
    <PageBody>
      <LoadingState label="Loading page…" />
    </PageBody>
  );
}

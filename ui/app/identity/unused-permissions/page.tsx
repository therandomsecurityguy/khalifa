'use client';

import { getUnusedPermissions } from '@/lib/api';
import type { ServiceActions } from '@/types';
import { PrincipalLookup } from '@/components/principal-lookup';
import { Card } from '@/components/ui';

function ServiceList({ title, groups }: { title: string; groups: ServiceActions[] }) {
  return (
    <Card title={title}>
      <div className="max-h-96 space-y-3 overflow-auto text-xs text-gray-700">
        {groups.length === 0
          ? 'None'
          : groups.map((group) => (
              <div key={group.service}>
                <div className="font-semibold">{group.service}</div>
                {group.actions.map((action) => (
                  <div key={action} className="font-mono">
                    {action}
                  </div>
                ))}
              </div>
            ))}
      </div>
    </Card>
  );
}

export default function UnusedPermissionsPage() {
  return (
    <PrincipalLookup
      title="Unused permissions"
      path="/identity/unused-permissions"
      load={getUnusedPermissions}
      prompt="Enter a principal ARN to compare used and unused actions."
    >
      {(data) => (
        <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
          <ServiceList title="Unused" groups={data.unusedActions} />
          <ServiceList title="Used" groups={data.usedActions} />
        </div>
      )}
    </PrincipalLookup>
  );
}

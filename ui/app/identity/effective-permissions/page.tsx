'use client';

import { getEffectivePermissions } from '@/lib/api';
import { PrincipalLookup } from '@/components/principal-lookup';
import { Card, RiskBadge, StatCard } from '@/components/ui';

function ActionList({ title, actions }: { title: string; actions: string[] }) {
  return (
    <Card title={`${title} (${actions.length})`}>
      <div className="max-h-64 overflow-auto font-mono text-xs text-gray-700">
        {actions.length === 0 ? 'None' : actions.map((action) => <div key={action}>{action}</div>)}
      </div>
    </Card>
  );
}

export default function EffectivePermissionsPage() {
  return (
    <PrincipalLookup
      title="Effective permissions"
      path="/identity/effective-permissions"
      load={getEffectivePermissions}
      prompt="Enter a principal ARN to evaluate permissions."
    >
      {(data) => (
        <div className="space-y-6">
          <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <StatCard
              label="Admin"
              value={
                data.isAdmin ? (
                  <span className="flex items-center gap-3">
                    Yes <RiskBadge level="high" />
                  </span>
                ) : (
                  'No'
                )
              }
            />
            <StatCard label="Blast radius" value={data.blastRadius} />
            <StatCard label="Allowed" value={data.allowedActions.length} />
            <StatCard label="Denied" value={data.deniedActions.length} />
          </div>
          <ActionList title="Allowed actions" actions={data.allowedActions} />
          <ActionList title="Denied actions" actions={data.deniedActions} />
          {data.conditionalGrants.length > 0 && (
            <Card title="Conditional grants">
              <pre className="max-h-64 overflow-auto text-xs text-gray-700">
                {JSON.stringify(data.conditionalGrants, null, 2)}
              </pre>
            </Card>
          )}
        </div>
      )}
    </PrincipalLookup>
  );
}

'use client';

import { getRightsizingRecommendation } from '@/lib/api';
import { PrincipalLookup } from '@/components/principal-lookup';
import { Card, RiskBadge } from '@/components/ui';

export default function RightsizingPage() {
  return (
    <PrincipalLookup
      title="Rightsizing"
      path="/identity/rightsizing"
      load={getRightsizingRecommendation}
      prompt="Enter a principal ARN to generate a recommendation."
    >
      {(data) => (
        <div className="space-y-6">
          <div className="flex items-center gap-3">
            <RiskBadge level={data.riskLevel} />
            <span className="text-sm text-gray-600">
              Confidence {(data.confidence * 100).toFixed(0)}% · {data.removedActions.length}{' '}
              removed · {data.keptActions.length} kept
            </span>
          </div>
          <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
            <Card title="Recommended policy">
              <pre className="max-h-96 overflow-auto text-xs">
                {JSON.stringify(data.recommendedPolicy, null, 2)}
              </pre>
            </Card>
            <Card title={`Removed actions (${data.removedActions.length})`}>
              <div className="max-h-96 overflow-auto font-mono text-xs">
                {data.removedActions.length === 0
                  ? 'None'
                  : data.removedActions.map((action) => <div key={action}>{action}</div>)}
              </div>
            </Card>
          </div>
        </div>
      )}
    </PrincipalLookup>
  );
}

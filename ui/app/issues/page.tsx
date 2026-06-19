'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { getIssues, getIssueCounts } from '@/lib/api';
import { Issue, SeverityCounts } from '@/types';

const severityColors: Record<string, string> = {
  critical: 'bg-red-600',
  high: 'bg-orange-500',
  medium: 'bg-yellow-500',
  low: 'bg-blue-500',
};

const severityLabels: Record<string, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
};

export default function IssuesPage() {
  const [issues, setIssues] = useState<Issue[]>([]);
  const [counts, setCounts] = useState<SeverityCounts | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  const [filters, setFilters] = useState({
    severity: [] as string[],
    team: '',
    status: 'open',
    limit: 50,
  });

  useEffect(() => {
    loadData();
  }, [filters]);

  async function loadData() {
    setLoading(true);
    setError(null);
    
    try {
      const [issuesRes, countsRes] = await Promise.all([
        getIssues(filters),
        getIssueCounts(),
      ]);
      
      setIssues(issuesRes.items);
      setCounts(countsRes);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load issues');
    } finally {
      setLoading(false);
    }
  }

  function handleFilterChange(key: string, value: any) {
    setFilters(prev => ({ ...prev, [key]: value }));
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <header className="bg-white shadow">
        <div className="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8">
          <h1 className="text-3xl font-bold text-gray-900">Security Issues</h1>
        </div>
      </header>

      <main className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        <div className="px-4 py-6 sm:px-0">
          {error && (
            <div className="mb-4 p-4 bg-red-50 border border-red-200 rounded-md">
              <p className="text-red-800">{error}</p>
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
            {counts && Object.entries(counts).map(([severity, count]) => (
              <div
                key={severity}
                className={`bg-white rounded-lg shadow p-6 border-l-4 ${severityColors[severity]}`}
              >
                <div className="text-sm font-medium text-gray-500 uppercase">
                  {severityLabels[severity]}
                </div>
                <div className="mt-2 text-3xl font-semibold text-gray-900">{count}</div>
              </div>
            ))}
          </div>

          <div className="bg-white shadow rounded-lg overflow-hidden">
            <div className="p-4 border-b border-gray-200 bg-gray-50">
              <div className="flex flex-wrap gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Severity</label>
                  <select
                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
                    onChange={(e) => handleFilterChange('severity', e.target.value ? [e.target.value] : [])}
                    value={filters.severity[0] || ''}
                  >
                    <option value="">All</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Team</label>
                  <input
                    type="text"
                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
                    placeholder="Filter by team"
                    value={filters.team}
                    onChange={(e) => handleFilterChange('team', e.target.value)}
                  />
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Status</label>
                  <select
                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
                    onChange={(e) => handleFilterChange('status', e.target.value)}
                    value={filters.status}
                  >
                    <option value="">All</option>
                    <option value="open">Open</option>
                    <option value="resolved">Resolved</option>
                    <option value="suppressed">Suppressed</option>
                  </select>
                </div>
              </div>
            </div>

            {loading ? (
              <div className="p-8 text-center text-gray-500">Loading...</div>
            ) : issues.length === 0 ? (
              <div className="p-8 text-center text-gray-500">No issues found</div>
            ) : (
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Severity</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Issue</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Resources</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Team</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Risk Score</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Created</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {issues.map((issue) => (
                      <tr key={issue.id} className="hover:bg-gray-50">
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${severityColors[issue.severity]} text-white`}>
                            {issue.severity}
                          </span>
                        </td>
                        <td className="px-6 py-4">
                          <div className="text-sm font-medium text-gray-900">{issue.ruleId}</div>
                          <div className="text-sm text-gray-500">{issue.metadata?.ruleName}</div>
                        </td>
                        <td className="px-6 py-4">
                          <div className="text-sm text-gray-900">
                            {issue.resourcesInvolved.slice(0, 2).map((r) => (
                              <div key={r.resourceId} className="truncate max-w-xs">
                                {r.resourceType}: {r.resourceName || r.resourceId}
                              </div>
                            ))}
                            {issue.resourcesInvolved.length > 2 && (
                              <div className="text-sm text-gray-500">
                                +{issue.resourcesInvolved.length - 2} more
                              </div>
                            )}
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                          {issue.owningTeam}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                          {issue.riskScore.toFixed(1)}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                          {new Date(issue.createdAt).toLocaleDateString()}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                          <Link
                            href={`/issues/${issue.id}`}
                            className="text-indigo-600 hover:text-indigo-900"
                          >
                            View
                          </Link>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}

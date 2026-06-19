'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import { getDriftReport } from '@/lib/api';

const frameworkLabels: Record<string, string> = {
  CIS_AWS_FOUNDATIONS: 'CIS AWS Foundations v3.0',
  SOC2: 'SOC 2 Type II',
  ISO27001: 'ISO 27001:2022',
};

const severityColors: Record<string, string> = {
  critical: 'bg-red-100 text-red-800',
  high: 'bg-orange-100 text-orange-800',
  medium: 'bg-yellow-100 text-yellow-800',
  low: 'bg-blue-100 text-blue-800',
};

export default function DriftReportPage() {
  const params = useParams();
  const framework = params.framework as string;

  const [drift, setDrift] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadDrift();
  }, [framework]);

  async function loadDrift() {
    setLoading(true);
    setError(null);
    try {
      const data = await getDriftReport(framework);
      setDrift(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load drift report');
    } finally {
      setLoading(false);
    }
  }

  function getSeverityColor(severity: string): string {
    return severityColors[severity] || 'bg-gray-100 text-gray-800';
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-gray-500">Loading drift report...</div>
      </div>
    );
  }

  if (error || !drift) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <h1 className="text-2xl font-bold text-gray-900">Drift Report Not Available</h1>
          <p className="mt-2 text-gray-600">{error || 'No drift data available'}</p>
          <Link href={`/compliance/${framework}`} className="mt-4 text-indigo-600 hover:text-indigo-900">
            Back to Framework
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <header className="bg-white shadow">
        <div className="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between">
            <div>
              <Link href={`/compliance/${framework}`} className="text-indigo-600 hover:text-indigo-900 text-sm font-medium mb-2 inline-block">
                ← {frameworkLabels[framework] || framework}
              </Link>
              <h1 className="text-3xl font-bold text-gray-900">Configuration Drift Report</h1>
              <p className="mt-1 text-gray-600">Detected compliance violations since last assessment</p>
            </div>
            <div className="flex items-center space-x-4">
              <span className="px-3 py-1 bg-red-100 text-red-800 rounded-full text-sm font-medium">
                {drift.totalDriftItems} Drift Items
              </span>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        <div className="px-4 py-6 sm:px-0">
          {error && (
            <div className="mb-4 p-4 bg-red-50 border border-red-200 rounded-md">
              <p className="text-red-800">{error}</p>
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
            <div className="p-4 bg-red-50 rounded-lg border-l-4 border-red-500">
              <div className="text-sm font-medium text-gray-500">Critical</div>
              <div className="mt-1 text-3xl font-bold text-red-600">{drift.criticalDrift}</div>
            </div>
            <div className="p-4 bg-orange-50 rounded-lg border-l-4 border-orange-500">
              <div className="text-sm font-medium text-gray-500">High</div>
              <div className="mt-1 text-3xl font-bold text-orange-600">{drift.highDrift}</div>
            </div>
            <div className="p-4 bg-yellow-50 rounded-lg border-l-4 border-yellow-500">
              <div className="text-sm font-medium text-gray-500">Medium</div>
              <div className="mt-1 text-3xl font-bold text-yellow-600">{drift.mediumDrift}</div>
            </div>
            <div className="p-4 bg-blue-50 rounded-lg border-l-4 border-blue-500">
              <div className="text-sm font-medium text-gray-500">Low</div>
              <div className="mt-1 text-3xl font-bold text-blue-600">{drift.lowDrift}</div>
            </div>
          </div>

          <div className="bg-white shadow rounded-lg overflow-hidden">
            {drift.driftItems.length === 0 ? (
              <div className="p-12 text-center">
                <svg className="mx-auto h-12 w-12 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <h3 className="mt-2 text-lg font-medium text-gray-900">No Configuration Drift Detected</h3>
                <p className="mt-1 text-gray-500">All automated controls are currently passing.</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Control ID</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Title</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Section</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Severity</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Detected</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Related Rules</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Remediation</th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {drift.driftItems.map((item: any) => (
                      <tr key={item.controlId} className="hover:bg-gray-50">
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{item.controlId}</td>
                        <td className="px-6 py-4">
                          <div className="text-sm font-medium text-gray-900">{item.controlTitle}</div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{item.section}</td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getSeverityColor(item.severity)}`}>
                            {item.severity}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{new Date(item.detectedAt).toLocaleString()}</td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                          {item.relatedRules?.join(', ') || '—'}
                        </td>
                        <td className="px-6 py-4 text-sm text-gray-600 max-w-md">
                          {item.remediation}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <div className="mt-6 p-4 bg-gray-50 rounded-lg">
            <p className="text-sm text-gray-600">
              <strong>Report Generated:</strong> {new Date(drift.generatedAt).toLocaleString()} |
              <strong> Framework:</strong> {frameworkLabels[framework] || framework}
            </p>
          </div>
        </div>
      </main>
    </div>
  );
}
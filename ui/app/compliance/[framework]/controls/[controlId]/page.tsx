'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import { getControlDetails, ComplianceControl } from '@/lib/api';

const frameworkLabels: Record<string, string> = {
  CIS_AWS_FOUNDATIONS: 'CIS AWS Foundations v3.0',
  SOC2: 'SOC 2 Type II',
  ISO27001: 'ISO 27001:2022',
};

const statusColors: Record<string, string> = {
  PASS: 'bg-green-100 text-green-800',
  FAIL: 'bg-red-100 text-red-800',
  MANUAL: 'bg-yellow-100 text-yellow-800',
  NOT_EVALUATED: 'bg-gray-100 text-gray-800',
  NOT_APPLICABLE: 'bg-blue-100 text-blue-800',
};

const severityColors: Record<string, string> = {
  critical: 'bg-red-100 text-red-800',
  high: 'bg-orange-100 text-orange-800',
  medium: 'bg-yellow-100 text-yellow-800',
  low: 'bg-blue-100 text-blue-800',
};

export default function ControlDetailPage() {
  const params = useParams();
  const framework = params.framework as string;
  const controlId = params.controlId as string;

  const [control, setControl] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadControl();
  }, [framework, controlId]);

  async function loadControl() {
    setLoading(true);
    setError(null);
    try {
      const data = await getControlDetails(framework, controlId);
      setControl(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load control details');
    } finally {
      setLoading(false);
    }
  }

  function getStatusColor(status: string): string {
    return statusColors[status] || 'bg-gray-100 text-gray-800';
  }

  function getSeverityColor(severity: string): string {
    return severityColors[severity] || 'bg-gray-100 text-gray-800';
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-gray-500">Loading control details...</div>
      </div>
    );
  }

  if (error || !control) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <h1 className="text-2xl font-bold text-gray-900">Control Not Found</h1>
          <p className="mt-2 text-gray-600">{error || `Control ${controlId} not found`}</p>
          <Link
            href={`/compliance/${framework}`}
            className="mt-4 text-indigo-600 hover:text-indigo-900"
          >
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
          <div className="flex items-center space-x-4">
            <Link
              href={`/compliance/${framework}`}
              className="text-indigo-600 hover:text-indigo-900 text-sm font-medium"
            >
              ← {frameworkLabels[framework] || framework}
            </Link>
            <div>
              <h1 className="text-2xl font-bold text-gray-900">{control.title}</h1>
              <p className="text-sm text-gray-500">Control ID: {control.id}</p>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        <div className="px-4 py-6 sm:px-0">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2 space-y-6">
              <div className="bg-white shadow rounded-lg p-6">
                <div className="flex flex-wrap items-center gap-4 mb-4">
                  <span
                    className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(control.status)}`}
                  >
                    {control.status}
                  </span>
                  <span
                    className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ${getSeverityColor(control.severity)}`}
                  >
                    {control.severity}
                  </span>
                  <span
                    className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ${control.automated ? 'bg-blue-100 text-blue-800' : 'bg-gray-100 text-gray-800'}`}
                  >
                    {control.automated ? 'Automated' : 'Manual'}
                  </span>
                </div>

                <div className="prose max-w-none">
                  <h3 className="text-lg font-medium text-gray-900 mb-2">Description</h3>
                  <p className="text-gray-600">
                    {control.description || 'No description available.'}
                  </p>
                </div>
              </div>

              <div className="bg-white shadow rounded-lg p-6">
                <h3 className="text-lg font-medium text-gray-900 mb-4">Remediation Guidance</h3>
                <div className="prose max-w-none text-gray-600">
                  <p>
                    {control.remediationHint ||
                      'Review and remediate the identified security issue according to best practices.'}
                  </p>
                </div>
              </div>

              {control.relatedRules && control.relatedRules.length > 0 && (
                <div className="bg-white shadow rounded-lg p-6">
                  <h3 className="text-lg font-medium text-gray-900 mb-4">Related Security Rules</h3>
                  <div className="flex flex-wrap gap-2">
                    {control.relatedRules.map((ruleId: string) => (
                      <span
                        key={ruleId}
                        className="px-3 py-1 bg-indigo-50 text-indigo-700 rounded-full text-sm font-medium"
                      >
                        {ruleId}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {control.evidence && control.evidence.length > 0 && (
                <div className="bg-white shadow rounded-lg p-6">
                  <h3 className="text-lg font-medium text-gray-900 mb-4">Evidence</h3>
                  <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-gray-200">
                      <thead className="bg-gray-50">
                        <tr>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            Resource
                          </th>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            Type
                          </th>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            Status
                          </th>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            Collected
                          </th>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            Details
                          </th>
                        </tr>
                      </thead>
                      <tbody className="bg-white divide-y divide-gray-200">
                        {control.evidence.map((evidence: any) => (
                          <tr key={evidence.resourceId} className="hover:bg-gray-50">
                            <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900 truncate max-w-xs">
                              {evidence.resourceId}
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                              {evidence.resourceType}
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap">
                              <span
                                className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(evidence.status)}`}
                              >
                                {evidence.status}
                              </span>
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                              {new Date(evidence.collectedAt).toLocaleString()}
                            </td>
                            <td className="px-6 py-4 text-sm text-gray-500 max-w-md">
                              <pre className="whitespace-pre-wrap text-xs">
                                {JSON.stringify(evidence.details, null, 2)}
                              </pre>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {control.relatedIssues && control.relatedIssues.length > 0 && (
                <div className="bg-white shadow rounded-lg p-6">
                  <h3 className="text-lg font-medium text-gray-900 mb-4">Related Open Issues</h3>
                  <ul className="divide-y divide-gray-200">
                    {control.relatedIssues.map((issue: any) => (
                      <li key={issue.ruleId} className="py-3">
                        <div className="flex items-center justify-between">
                          <div>
                            <span className="font-medium text-gray-900">{issue.ruleId}</span>
                            <span className="ml-2 px-2 py-0.5 text-xs rounded-full bg-gray-100 text-gray-600">
                              {issue.status}
                            </span>
                          </div>
                          <span
                            className={`px-2 py-0.5 text-xs rounded-full ${getSeverityColor(issue.severity)}`}
                          >
                            {issue.severity}
                          </span>
                        </div>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>

            <div className="space-y-6">
              <div className="bg-white shadow rounded-lg p-6">
                <h3 className="text-lg font-medium text-gray-900 mb-4">Control Metadata</h3>
                <dl className="divide-y divide-gray-200">
                  <div className="py-3 flex justify-between">
                    <dt className="text-sm font-medium text-gray-500">Framework</dt>
                    <dd className="text-sm text-gray-900">
                      {frameworkLabels[framework] || framework}
                    </dd>
                  </div>
                  <div className="py-3 flex justify-between">
                    <dt className="text-sm font-medium text-gray-500">Section</dt>
                    <dd className="text-sm text-gray-900">{control.section}</dd>
                  </div>
                  <div className="py-3 flex justify-between">
                    <dt className="text-sm font-medium text-gray-500">Severity</dt>
                    <dd className="text-sm text-gray-900">
                      <span
                        className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${getSeverityColor(control.severity)}`}
                      >
                        {control.severity}
                      </span>
                    </dd>
                  </div>
                  <div className="py-3 flex justify-between">
                    <dt className="text-sm font-medium text-gray-500">Type</dt>
                    <dd className="text-sm text-gray-900">
                      {control.automated ? 'Automated' : 'Manual'}
                    </dd>
                  </div>
                  <div className="py-3 flex justify-between">
                    <dt className="text-sm font-medium text-gray-500">Last Evaluated</dt>
                    <dd className="text-sm text-gray-900">
                      {control.lastEvaluated
                        ? new Date(control.lastEvaluated).toLocaleString()
                        : 'Never'}
                    </dd>
                  </div>
                </dl>
              </div>

              {control.evidenceRequirements && control.evidenceRequirements.length > 0 && (
                <div className="bg-white shadow rounded-lg p-6">
                  <h3 className="text-lg font-medium text-gray-900 mb-4">Evidence Requirements</h3>
                  <ul className="list-disc list-inside space-y-2 text-gray-600">
                    {control.evidenceRequirements.map((req: string, i: number) => (
                      <li key={i}>{req}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}

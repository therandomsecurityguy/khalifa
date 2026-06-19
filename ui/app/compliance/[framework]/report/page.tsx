'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import { getComplianceReport, ComplianceControl } from '@/lib/api';

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

export default function ComplianceReportPage() {
  const params = useParams();
  const framework = params.framework as string;

  const [report, setReport] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [format, setFormat] = useState<'json' | 'csv'>('json');

  useEffect(() => {
    loadReport();
  }, [framework]);

  async function loadReport() {
    setLoading(true);
    setError(null);
    try {
      const data = await getComplianceReport(framework, format);
      setReport(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load report');
    } finally {
      setLoading(false);
    }
  }

  async function downloadReport() {
    try {
      const response = await fetch(`/api/compliance/${framework}/report?format=csv`, {
        headers: {
          Authorization: `Bearer ${localStorage.getItem('id_token')}`,
        },
      });
      if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${framework}-compliance-report-${new Date().toISOString().split('T')[0]}.csv`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
      }
    } catch (err) {
      console.error('Download failed:', err);
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
        <div className="text-gray-500">Loading report...</div>
      </div>
    );
  }

  if (error || !report) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <h1 className="text-2xl font-bold text-gray-900">Report Not Available</h1>
          <p className="mt-2 text-gray-600">{error || 'No report data available'}</p>
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
          <div className="flex items-center justify-between">
            <div>
              <Link
                href={`/compliance/${framework}`}
                className="text-indigo-600 hover:text-indigo-900 text-sm font-medium mb-2 inline-block"
              >
                ← {frameworkLabels[framework] || framework}
              </Link>
              <h1 className="text-3xl font-bold text-gray-900">Compliance Report</h1>
            </div>
            <div className="flex items-center space-x-4">
              <select
                value={format}
                onChange={(e) => setFormat(e.target.value as 'json' | 'csv')}
                className="px-3 py-2 border border-gray-300 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
              >
                <option value="json">JSON View</option>
                <option value="csv">CSV Export</option>
              </select>
              <button
                onClick={downloadReport}
                className="px-4 py-2 bg-indigo-600 text-white rounded-md text-sm font-medium hover:bg-indigo-700"
              >
                Download CSV
              </button>
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

          <div className="mb-8">
            <h2 className="text-xl font-bold text-gray-900 mb-4">Executive Summary</h2>
            <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
              <div className="p-4 bg-white rounded-lg shadow">
                <div className="text-sm font-medium text-gray-500">Total Controls</div>
                <div className="mt-1 text-3xl font-bold text-gray-900">
                  {report.summary.totalControls}
                </div>
              </div>
              <div className="p-4 bg-green-50 rounded-lg">
                <div className="text-sm font-medium text-gray-500">Passed</div>
                <div className="mt-1 text-3xl font-bold text-green-600">
                  {report.summary.passed}
                </div>
              </div>
              <div className="p-4 bg-red-50 rounded-lg">
                <div className="text-sm font-medium text-gray-500">Failed</div>
                <div className="mt-1 text-3xl font-bold text-red-600">{report.summary.failed}</div>
              </div>
              <div className="p-4 bg-yellow-50 rounded-lg">
                <div className="text-sm font-medium text-gray-500">Manual</div>
                <div className="mt-1 text-3xl font-bold text-yellow-600">
                  {report.summary.manual}
                </div>
              </div>
              <div className="p-4 bg-gray-50 rounded-lg">
                <div className="text-sm font-medium text-gray-500">Not Evaluated</div>
                <div className="mt-1 text-3xl font-bold text-gray-600">
                  {report.summary.notEvaluated}
                </div>
              </div>
              <div className="p-4 bg-indigo-50 rounded-lg">
                <div className="text-sm font-medium text-gray-500">Coverage</div>
                <div className="mt-1 text-3xl font-bold text-indigo-600">
                  {report.summary.coveragePercent}%
                </div>
              </div>
            </div>

            <div className="mt-6 p-4 bg-gray-50 rounded-lg">
              <p className="text-gray-700">
                <strong>Assessment Date:</strong> {new Date(report.generatedAt).toLocaleString()} |
                <strong> Framework:</strong> {frameworkLabels[framework] || framework} |
                <strong> Coverage:</strong> {report.summary.coveragePercent}% of automated controls
                evaluated
              </p>
            </div>
          </div>

          <div className="bg-white shadow rounded-lg overflow-hidden">
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Control ID
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Title
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Section
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Severity
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Type
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Status
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Issues
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {report.controls.map((control: any) => (
                    <tr key={control.control.id} className="hover:bg-gray-50">
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                        {control.control.id}
                      </td>
                      <td className="px-6 py-4">
                        <div
                          className="text-sm text-gray-900 max-w-md truncate"
                          title={control.control.title}
                        >
                          {control.control.title}
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {control.control.section}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span
                          className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getSeverityColor(control.control.severity)}`}
                        >
                          {control.control.severity}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {control.control.automated ? 'Automated' : 'Manual'}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span
                          className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(control.status)}`}
                        >
                          {control.status}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-500">
                        {control.issues && control.issues.length > 0 ? (
                          <ul className="list-disc list-inside">
                            {control.issues.map((issue: string, i: number) => (
                              <li key={i}>{issue}</li>
                            ))}
                          </ul>
                        ) : (
                          '—'
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}

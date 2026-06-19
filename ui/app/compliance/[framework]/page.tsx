'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import { getFrameworkSummary, getFrameworkControls, getControlDetails, getDriftReport, getComplianceReport, ComplianceControl } from '@/lib/api';

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

export default function FrameworkDetailPage() {
  const params = useParams();
  const framework = params.framework as string;

  const [summary, setSummary] = useState<any>(null);
  const [controls, setControls] = useState<ComplianceControl[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filters, setFilters] = useState({
    section: '',
    status: '',
    severity: '',
    automated: '',
  });

  useEffect(() => {
    loadData();
  }, [framework]);

  async function loadData() {
    setLoading(true);
    setError(null);
    try {
      const [summaryRes, controlsRes] = await Promise.all([
        getFrameworkSummary(framework),
        getFrameworkControls(framework),
      ]);
      setSummary(summaryRes);
      setControls(controlsRes.controls);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load framework data');
    } finally {
      setLoading(false);
    }
  }

  const filteredControls = controls.filter((control) => {
    if (filters.section && control.section !== filters.section) return false;
    if (filters.status && control.status !== filters.status) return false;
    if (filters.severity && control.severity !== filters.severity) return false;
    if (filters.automated !== '' && control.automated !== (filters.automated === 'true')) return false;
    return true;
  });

  const sections = [...new Set(controls.map(c => c.section))].sort();

  function getStatusColor(status: string): string {
    return statusColors[status] || 'bg-gray-100 text-gray-800';
  }

  function getSeverityColor(severity: string): string {
    return severityColors[severity] || 'bg-gray-100 text-gray-800';
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <header className="bg-white shadow">
        <div className="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between">
            <div>
              <Link href="/compliance" className="text-indigo-600 hover:text-indigo-900 text-sm font-medium mb-2 inline-block">
                ← Back to Compliance
              </Link>
              <h1 className="text-3xl font-bold text-gray-900">{frameworkLabels[framework] || framework}</h1>
            </div>
            <div className="flex space-x-3">
              <Link
                href={`/compliance/${framework}/report`}
                className="px-4 py-2 bg-indigo-600 text-white rounded-md text-sm font-medium hover:bg-indigo-700"
              >
                Download Report
              </Link>
              <Link
                href={`/compliance/${framework}/drift`}
                className="px-4 py-2 bg-gray-100 text-gray-700 rounded-md text-sm font-medium hover:bg-gray-200"
              >
                View Drift
              </Link>
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

          {loading ? (
            <div className="p-8 text-center text-gray-500">Loading...</div>
          ) : summary && (
            <>
              <div className="grid grid-cols-2 md:grid-cols-6 gap-4 mb-6">
                <div className="p-4 bg-white rounded-lg shadow">
                  <div className="text-sm font-medium text-gray-500">Total Controls</div>
                  <div className="mt-1 text-3xl font-bold text-gray-900">{summary.totalControls}</div>
                </div>
                <div className="p-4 bg-green-50 rounded-lg">
                  <div className="text-sm font-medium text-gray-500">Passed</div>
                  <div className="mt-1 text-3xl font-bold text-green-600">{summary.passed}</div>
                </div>
                <div className="p-4 bg-red-50 rounded-lg">
                  <div className="text-sm font-medium text-gray-500">Failed</div>
                  <div className="mt-1 text-3xl font-bold text-red-600">{summary.failed}</div>
                </div>
                <div className="p-4 bg-yellow-50 rounded-lg">
                  <div className="text-sm font-medium text-gray-500">Manual</div>
                  <div className="mt-1 text-3xl font-bold text-yellow-600">{summary.manual}</div>
                </div>
                <div className="p-4 bg-blue-50 rounded-lg">
                  <div className="text-sm font-medium text-gray-500">Automated</div>
                  <div className="mt-1 text-3xl font-bold text-blue-600">{summary.automatedControls}</div>
                </div>
                <div className="p-4 bg-indigo-50 rounded-lg">
                  <div className="text-sm font-medium text-gray-500">Coverage</div>
                  <div className="mt-1 text-3xl font-bold text-indigo-600">{summary.coveragePercent}%</div>
                </div>
              </div>

              <div className="bg-white shadow rounded-lg overflow-hidden">
                <div className="p-4 border-b border-gray-200 bg-gray-50">
                  <div className="flex flex-wrap gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Section</label>
                      <select
                        className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
                        onChange={(e) => setFilters(prev => ({ ...prev, section: e.target.value }))}
                        value={filters.section}
                      >
                        <option value="">All Sections</option>
                        {sections.map(s => <option key={s} value={s}>{s}</option>)}
                      </select>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Status</label>
                      <select
                        className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
                        onChange={(e) => setFilters(prev => ({ ...prev, status: e.target.value }))}
                        value={filters.status}
                      >
                        <option value="">All Statuses</option>
                        <option value="PASS">Pass</option>
                        <option value="FAIL">Fail</option>
                        <option value="MANUAL">Manual</option>
                        <option value="NOT_EVALUATED">Not Evaluated</option>
                        <option value="NOT_APPLICABLE">N/A</option>
                      </select>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Severity</label>
                      <select
                        className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
                        onChange={(e) => setFilters(prev => ({ ...prev, severity: e.target.value }))}
                        value={filters.severity}
                      >
                        <option value="">All Severities</option>
                        <option value="critical">Critical</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                      </select>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Type</label>
                      <select
                        className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
                        onChange={(e) => setFilters(prev => ({ ...prev, automated: e.target.value }))}
                        value={filters.automated}
                      >
                        <option value="">All</option>
                        <option value="true">Automated</option>
                        <option value="false">Manual</option>
                      </select>
                    </div>
                  </div>
                </div>

                {filteredControls.length === 0 ? (
                  <div className="p-8 text-center text-gray-500">No controls match the current filters</div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-gray-200">
                      <thead className="bg-gray-50">
                        <tr>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Control ID</th>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Title</th>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Section</th>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Severity</th>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Type</th>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Related Rules</th>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                        </tr>
                      </thead>
                      <tbody className="bg-white divide-y divide-gray-200">
                        {filteredControls.map((control) => (
                          <tr key={control.id} className="hover:bg-gray-50">
                            <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{control.id}</td>
                            <td className="px-6 py-4">
                              <div className="text-sm text-gray-900 max-w-md truncate" title={control.title}>{control.title}</div>
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{control.section}</td>
                            <td className="px-6 py-4 whitespace-nowrap">
                              <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getSeverityColor(control.severity)}`}>
                                {control.severity}
                              </span>
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                              {control.automated ? 'Automated' : 'Manual'}
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap">
                              <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(control.status)}`}>
                                {control.status}
                              </span>
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                              {control.relatedRules?.join(', ') || '—'}
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                              <Link
                                href={`/compliance/${framework}/controls/${control.id}`}
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
            </>
          )}
        </div>
      </main>
    </div>
  );
}
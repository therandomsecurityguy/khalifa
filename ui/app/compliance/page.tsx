'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { getFrameworks, getFrameworkSummary, ComplianceFrameworkSummary } from '@/lib/api';

const frameworkLabels: Record<string, string> = {
  CIS_AWS_FOUNDATIONS: 'CIS AWS Foundations v3.0',
  SOC2: 'SOC 2 Type II',
  ISO27001: 'ISO 27001:2022',
};

const frameworkDescriptions: Record<string, string> = {
  CIS_AWS_FOUNDATIONS: 'CIS Amazon Web Services Foundations Benchmark v3.0.0 - 78 controls across 5 sections',
  SOC2: 'SOC 2 Type II Trust Services Criteria - 22 controls across CC6, CC7, CC8',
  ISO27001: 'ISO/IEC 27001:2022 Annex A - 24 controls across A.5, A.6, A.8, A.9, A.10, A.12, A.13',
};

const statusColors: Record<string, string> = {
  PASS: 'bg-green-100 text-green-800',
  FAIL: 'bg-red-100 text-red-800',
  MANUAL: 'bg-yellow-100 text-yellow-800',
  NOT_EVALUATED: 'bg-gray-100 text-gray-800',
  NOT_APPLICABLE: 'bg-blue-100 text-blue-800',
};

export default function CompliancePage() {
  const [frameworks, setFrameworks] = useState<ComplianceFrameworkSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadFrameworks();
  }, []);

  async function loadFrameworks() {
    setLoading(true);
    setError(null);
    try {
      const data = await getFrameworks();
      setFrameworks(data.frameworks);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load compliance frameworks');
    } finally {
      setLoading(false);
    }
  }

  function getStatusColor(status: string): string {
    return statusColors[status] || 'bg-gray-100 text-gray-800';
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <header className="bg-white shadow">
        <div className="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8">
          <h1 className="text-3xl font-bold text-gray-900">Compliance Posture</h1>
          <p className="mt-2 text-gray-600">Monitor compliance across CIS, SOC 2, and ISO 27001 frameworks</p>
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
            <div className="p-8 text-center text-gray-500">Loading compliance frameworks...</div>
          ) : (
            <div className="space-y-6">
              {frameworks.map((framework) => (
                <div key={framework.framework} className="bg-white shadow rounded-lg overflow-hidden">
                  <div className="p-6">
                    <div className="flex flex-col md:flex-row md:items-center md:justify-between mb-4">
                      <div>
                        <Link href={`/compliance/${framework.framework}`} className="text-2xl font-bold text-gray-900 hover:text-indigo-600">
                          {frameworkLabels[framework.framework] || framework.framework}
                        </Link>
                        <p className="mt-1 text-sm text-gray-500">{frameworkDescriptions[framework.framework]}</p>
                      </div>
                      <div className="mt-4 md:mt-0 flex items-center space-x-4">
                        <div className="text-right">
                          <div className="text-3xl font-bold text-gray-900">{framework.coveragePercent}%</div>
                          <div className="text-sm text-gray-500">Coverage</div>
                        </div>
                        <div className="w-24 h-24">
                          <svg viewBox="0 0 36 36" className="transform -rotate-90">
                            <circle
                              cx="18"
                              cy="18"
                              r="15.915"
                              fill="none"
                              stroke="#e5e7eb"
                              strokeWidth="3"
                            />
                            <circle
                              cx="18"
                              cy="18"
                              r="15.915"
                              fill="none"
                              stroke="#3b82f6"
                              strokeWidth="3"
                              strokeDasharray={`${(framework.coveragePercent / 100) * 100}, 100`}
                              strokeLinecap="round"
                              className="transition-all duration-500"
                            />
                          </svg>
                        </div>
                      </div>
                    </div>

                    <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                      <div className="p-4 bg-green-50 rounded-lg">
                        <div className="text-2xl font-bold text-green-600">{framework.summary.passed}</div>
                        <div className="text-sm text-gray-600">Passed</div>
                      </div>
                      <div className="p-4 bg-red-50 rounded-lg">
                        <div className="text-2xl font-bold text-red-600">{framework.summary.failed}</div>
                        <div className="text-sm text-gray-600">Failed</div>
                      </div>
                      <div className="p-4 bg-yellow-50 rounded-lg">
                        <div className="text-2xl font-bold text-yellow-600">{framework.summary.manual}</div>
                        <div className="text-sm text-gray-600">Manual</div>
                      </div>
                      <div className="p-4 bg-gray-50 rounded-lg">
                        <div className="text-2xl font-bold text-gray-600">{framework.summary.notEvaluated}</div>
                        <div className="text-sm text-gray-600">Not Evaluated</div>
                      </div>
                      <div className="p-4 bg-blue-50 rounded-lg">
                        <div className="text-2xl font-bold text-blue-600">{framework.summary.notApplicable}</div>
                        <div className="text-sm text-gray-600">N/A</div>
                      </div>
                    </div>

                    <div className="mt-4 flex items-center text-sm text-gray-500">
                      <span>Last assessed: </span>
                      <span className="font-medium ml-1">{new Date(framework.lastAssessment).toLocaleString()}</span>
                      <span className="mx-2">|</span>
                      <span>Version: {framework.version}</span>
                    </div>
                  </div>

                  <div className="border-t border-gray-200 px-6 py-4 bg-gray-50">
                    <Link
                      href={`/compliance/${framework.framework}`}
                      className="text-indigo-600 hover:text-indigo-900 font-medium text-sm flex items-center"
                    >
                      View Details
                      <svg className="ml-1 w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                      </svg>
                    </Link>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
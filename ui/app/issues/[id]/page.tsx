'use client';

import { useState, useEffect } from 'react';
import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import { getIssue } from '@/lib/api';
import { IssueDetail, GraphVertex, GraphEdge } from '@/types';

const severityColors: Record<string, string> = {
  critical: 'bg-red-600',
  high: 'bg-orange-500',
  medium: 'bg-yellow-500',
  low: 'bg-blue-500',
};

export default function IssueDetailPage() {
  const params = useParams();
  const router = useRouter();
  const [issue, setIssue] = useState<IssueDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (params.id) {
      loadIssue(params.id as string);
    }
  }, [params.id]);

  async function loadIssue(id: string) {
    setLoading(true);
    setError(null);
    
    try {
      const data = await getIssue(id);
      setIssue(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load issue');
    } finally {
      setLoading(false);
    }
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <p className="text-gray-500">Loading...</p>
      </div>
    );
  }

  if (error || !issue) {
    return (
      <div className="min-h-screen bg-gray-50">
        <div className="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8">
          <div className="p-4 bg-red-50 border border-red-200 rounded-md">
            <p className="text-red-800">{error || 'Issue not found'}</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <header className="bg-white shadow">
        <div className="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8 flex items-center justify-between">
          <div>
            <Link href="/issues" className="text-indigo-600 hover:text-indigo-900 text-sm mb-2 inline-block">
              ← Back to Issues
            </Link>
            <h1 className="text-2xl font-bold text-gray-900">{issue.ruleId}</h1>
          </div>
          <span className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium text-white ${severityColors[issue.severity]}`}>
            {issue.severity.toUpperCase()}
          </span>
        </div>
      </header>

      <main className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        <div className="px-4 py-6 sm:px-0">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2">
              <div className="bg-white shadow rounded-lg p-6 mb-6">
                <h2 className="text-lg font-medium text-gray-900 mb-4">Issue Details</h2>
                <dl className="grid grid-cols-1 gap-x-4 gap-y-4 sm:grid-cols-2">
                  <div>
                    <dt className="text-sm font-medium text-gray-500">Status</dt>
                    <dd className="mt-1 text-sm text-gray-900">{issue.status}</dd>
                  </div>
                  <div>
                    <dt className="text-sm font-medium text-gray-500">Owning Team</dt>
                    <dd className="mt-1 text-sm text-gray-900">{issue.owningTeam}</dd>
                  </div>
                  <div>
                    <dt className="text-sm font-medium text-gray-500">Risk Score</dt>
                    <dd className="mt-1 text-sm text-gray-900">{issue.riskScore.toFixed(2)}</dd>
                  </div>
                  <div>
                    <dt className="text-sm font-medium text-gray-500">Created</dt>
                    <dd className="mt-1 text-sm text-gray-900">
                      {new Date(issue.createdAt).toLocaleString()}
                    </dd>
                  </div>
                </dl>
                
                <div className="mt-6">
                  <dt className="text-sm font-medium text-gray-500">Remediation Hint</dt>
                  <dd className="mt-2 text-sm text-gray-900 bg-gray-50 p-4 rounded-md">
                    {issue.remediationHint}
                  </dd>
                </div>
              </div>

              <div className="bg-white shadow rounded-lg p-6">
                <h2 className="text-lg font-medium text-gray-900 mb-4">Attack Path</h2>
                <AttackPathVisualization
                  nodes={issue.attackPath?.nodes || []}
                  edges={issue.attackPath?.edges || []}
                />
              </div>
            </div>

            <div className="lg:col-span-1">
              <div className="bg-white shadow rounded-lg p-6">
                <h2 className="text-lg font-medium text-gray-900 mb-4">Involved Resources</h2>
                <ul className="divide-y divide-gray-200">
                  {issue.resourcesInvolved.map((resource, index) => (
                    <li key={index} className="py-3">
                      <div className="text-sm font-medium text-gray-900">
                        {resource.resourceType}
                      </div>
                      <div className="text-sm text-gray-500 truncate">
                        {resource.resourceName || resource.resourceId}
                      </div>
                      {resource.accountId && (
                        <div className="text-xs text-gray-400">
                          {resource.accountId} ({resource.region})
                        </div>
                      )}
                    </li>
                  ))}
                </ul>
              </div>

              {issue.metadata && (
                <div className="bg-white shadow rounded-lg p-6 mt-6">
                  <h2 className="text-lg font-medium text-gray-900 mb-4">Scoring Factors</h2>
                  {issue.metadata.scoringFactors && (
                    <dl className="space-y-2">
                      {Object.entries(issue.metadata.scoringFactors).map(([key, value]) => (
                        <div key={key} className="flex justify-between">
                          <dt className="text-sm text-gray-500">{key}</dt>
                          <dd className="text-sm font-medium text-gray-900">
                            {typeof value === 'number' ? value.toFixed(2) : String(value)}
                          </dd>
                        </div>
                      ))}
                    </dl>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}

function AttackPathVisualization({ nodes, edges }: { nodes: GraphVertex[]; edges: GraphEdge[] }) {
  if (nodes.length === 0) {
    return <p className="text-sm text-gray-500">No attack path data available</p>;
  }

  const nodeColors: Record<string, string> = {
    Internet: 'bg-red-500',
    EC2Instance: 'bg-blue-500',
    Lambda: 'bg-purple-500',
    IAMRole: 'bg-yellow-500',
    S3Bucket: 'bg-green-500',
    RDSInstance: 'bg-orange-500',
    KubernetesPod: 'bg-pink-500',
    ContainerImage: 'bg-indigo-500',
    SecurityGroup: 'bg-gray-500',
    Database: 'bg-teal-500',
    Secret: 'bg-amber-500',
  };

  return (
    <div className="space-y-2">
      <div className="relative">
        <div className="flex items-center justify-between">
          {nodes.map((node, index) => (
            <div key={node.id} className="flex items-center">
              <div className="flex flex-col items-center">
                <div className={`w-12 h-12 rounded-full flex items-center justify-center text-white text-xs font-medium ${nodeColors[node.label] || 'bg-gray-500'}`}>
                  <span className="text-center truncate px-1">{node.label}</span>
                </div>
                <div className="mt-2 text-xs text-gray-500 text-center max-w-[100px] truncate">
                  {node.properties?.name || node.properties?.arn?.slice(-20) || node.id.slice(0, 8)}
                </div>
              </div>
              {index < nodes.length - 1 && (
                <div className="mx-2">
                  <svg className="w-8 h-8 text-gray-400" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M7.293 14.707a1 1 0 010-1.414L10.586 10 7.293 6.707a1 1 0 011.414-1.414l4 4a1 1 0 010 1.414l-4 4a1 1 0 01-1.414 0z" clipRule="evenodd" />
                  </svg>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      <div className="mt-4 text-sm text-gray-500">
        <p>Path length: {nodes.length} nodes, {edges.length} edges</p>
      </div>
    </div>
  );
}

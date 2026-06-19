'use client';

import { useState } from 'react';
import { getAttackPaths } from '@/lib/api';
import { GraphVertex, GraphEdge } from '@/types';

export default function AttackPathsPage() {
  const [fromSelector, setFromSelector] = useState('Internet');
  const [toSelector, setToSelector] = useState('EC2Instance');
  const [maxPathLength, setMaxPathLength] = useState(4);
  const [results, setResults] = useState<{ nodes: GraphVertex[]; edges: GraphEdge[] } | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSearch() {
    setLoading(true);
    setError(null);

    try {
      const data = await getAttackPaths(fromSelector, toSelector, maxPathLength);
      setResults(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to find attack paths');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <header className="bg-white shadow">
        <div className="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8">
          <h1 className="text-3xl font-bold text-gray-900">Attack Path Explorer</h1>
        </div>
      </header>

      <main className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        <div className="px-4 py-6 sm:px-0">
          <div className="bg-white shadow rounded-lg p-6 mb-6">
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  From Selector
                </label>
                <input
                  type="text"
                  className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
                  value={fromSelector}
                  onChange={(e) => setFromSelector(e.target.value)}
                  placeholder="e.g., Internet, EC2Instance"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">To Selector</label>
                <input
                  type="text"
                  className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
                  value={toSelector}
                  onChange={(e) => setToSelector(e.target.value)}
                  placeholder="e.g., S3Bucket, CrownJewel"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Max Path Length
                </label>
                <input
                  type="number"
                  className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
                  value={maxPathLength}
                  onChange={(e) => setMaxPathLength(parseInt(e.target.value, 10))}
                  min={1}
                  max={10}
                />
              </div>

              <div className="flex items-end">
                <button
                  onClick={handleSearch}
                  disabled={loading}
                  className="w-full bg-indigo-600 border border-transparent rounded-md py-2 px-4 text-sm font-medium text-white hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50"
                >
                  {loading ? 'Searching...' : 'Find Paths'}
                </button>
              </div>
            </div>
          </div>

          {error && (
            <div className="mb-4 p-4 bg-red-50 border border-red-200 rounded-md">
              <p className="text-red-800">{error}</p>
            </div>
          )}

          {results && (
            <div className="bg-white shadow rounded-lg p-6">
              <h2 className="text-lg font-medium text-gray-900 mb-4">
                Found {results.nodes.length} nodes and {results.edges.length} edges
              </h2>

              {results.nodes.length > 0 ? (
                <div className="space-y-4">
                  <div>
                    <h3 className="text-sm font-medium text-gray-500 mb-2">Nodes</h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
                      {results.nodes.map((node) => (
                        <div key={node.id} className="bg-gray-50 rounded p-3">
                          <div className="text-sm font-medium text-gray-900">{node.label}</div>
                          <div className="text-xs text-gray-500 truncate">{node.id}</div>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div>
                    <h3 className="text-sm font-medium text-gray-500 mb-2">Edges</h3>
                    <ul className="divide-y divide-gray-200">
                      {results.edges.map((edge) => (
                        <li key={edge.id} className="py-2">
                          <div className="text-sm">
                            <span className="text-gray-500">{edge.from}</span>
                            <span className="mx-2 text-gray-400">→</span>
                            <span className="text-gray-500">{edge.to}</span>
                            <span className="ml-2 text-xs text-gray-400">({edge.label})</span>
                          </div>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              ) : (
                <p className="text-gray-500">No attack paths found with the given criteria.</p>
              )}
            </div>
          )}
        </div>
      </main>
    </div>
  );
}

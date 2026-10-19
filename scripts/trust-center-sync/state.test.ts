import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  CHANGELOG_LIMIT,
  currentPosture,
  diffPosture,
  loadPreviousState,
  nextState,
} from './state';
import type { PostureState, PublishableResponse } from './types';

describe('currentPosture', () => {
  it('keys published requirements by framework and requirement', () => {
    const posture = currentPosture({
      status: 'OK',
      generatedAt: null,
      requirements: [
        { requirement: '1.5', title: 't', section: 's', status: 'PASS' },
        { requirement: '2.1', title: 't', section: 's', status: 'FAIL' },
      ],
      mappedFrameworks: [
        { framework: 'SOC2', requirement: 'CC9.1', title: 't', section: 's', status: 'PASS' },
      ],
    } satisfies PublishableResponse);
    expect(posture).toEqual({
      'CIS_AWS_FOUNDATIONS:1.5': 'implemented',
      'CIS_AWS_FOUNDATIONS:2.1': 'partial',
      'SOC2:CC9.1': 'implemented',
    });
  });
});

describe('diffPosture', () => {
  const now = '2026-10-16T00:00:00.000Z';

  it('has no changes without a previous publish', () => {
    expect(diffPosture(null, { 'CIS_AWS_FOUNDATIONS:1.5': 'implemented' }, now)).toEqual([]);
  });

  it('records new, changed and removed requirements', () => {
    const changes = diffPosture(
      {
        'CIS_AWS_FOUNDATIONS:1.5': 'implemented',
        'CIS_AWS_FOUNDATIONS:2.1': 'partial',
        'SOC2:CC9.1': 'implemented',
      },
      {
        'CIS_AWS_FOUNDATIONS:1.5': 'partial',
        'CIS_AWS_FOUNDATIONS:3.1': 'implemented',
      },
      now
    );
    expect(changes.map((change) => change.title)).toEqual([
      'CIS AWS Foundations Benchmark v3.0.0 1.5 moved to partial',
      'CIS AWS Foundations Benchmark v3.0.0 3.1 is now published',
      'CIS AWS Foundations Benchmark v3.0.0 2.1 is no longer published',
      'SOC 2 Trust Services Criteria CC9.1 is no longer published',
    ]);
    expect(changes[0].description).toBe('Previously implemented.');
  });
});

describe('loadPreviousState', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'trust-center-state-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('reads the local posture-state.json first', async () => {
    const state: PostureState = {
      updatedAt: '2026-10-15T00:00:00.000Z',
      posture: { 'CIS_AWS_FOUNDATIONS:1.5': 'implemented' },
      changelog: [{ date: '2026-10-15T00:00:00.000Z', title: 'seeded' }],
    };
    writeFileSync(join(dir, 'posture-state.json'), JSON.stringify(state));
    const loaded = await loadPreviousState({ outDir: dir, publicUrl: 'https://unused.example' });
    expect(loaded).toEqual(state);
  });

  it('falls back to the deployed site and tolerates failures', async () => {
    const fetchImpl = jest.fn(async () => ({
      ok: true,
      text: async () =>
        JSON.stringify({ updatedAt: 'x', posture: { 'SOC2:CC9.1': 'partial' }, changelog: [] }),
    })) as unknown as typeof fetch;
    const loaded = await loadPreviousState({
      outDir: dir,
      publicUrl: 'https://trust.example.com/',
      fetchImpl,
    });
    expect(loaded?.posture).toEqual({ 'SOC2:CC9.1': 'partial' });
    expect((fetchImpl as jest.Mock).mock.calls[0][0]).toBe(
      'https://trust.example.com/posture-state.json'
    );

    const broken = jest.fn(async () => ({ ok: false, status: 404 })) as unknown as typeof fetch;
    const logs: string[] = [];
    expect(
      await loadPreviousState({
        outDir: dir,
        publicUrl: 'https://trust.example.com',
        fetchImpl: broken,
        log: (line) => logs.push(line),
      })
    ).toBeNull();
    expect(logs.join(' ')).toContain('HTTP 404');
  });

  it('ignores malformed local state', async () => {
    writeFileSync(join(dir, 'posture-state.json'), 'not-json');
    expect(await loadPreviousState({ outDir: dir })).toBeNull();
  });
});

describe('nextState', () => {
  it('carries the rolling changelog, newest first, capped', () => {
    const previous: PostureState = {
      updatedAt: '2026-10-15T00:00:00.000Z',
      posture: {},
      changelog: Array.from({ length: CHANGELOG_LIMIT }, (_, index) => ({
        date: `2026-09-${String(index + 1).padStart(2, '0')}T00:00:00.000Z`,
        title: `old ${index}`,
      })),
    };
    const state = nextState(
      previous,
      { 'CIS_AWS_FOUNDATIONS:1.5': 'partial' },
      [{ date: '2026-10-16T00:00:00.000Z', title: 'fresh' }],
      new Date('2026-10-16T00:00:00.000Z')
    );
    expect(state.changelog).toHaveLength(CHANGELOG_LIMIT);
    expect(state.changelog[0].title).toBe('fresh');
    expect(state.updatedAt).toBe('2026-10-16T00:00:00.000Z');
    expect(state.posture).toEqual({ 'CIS_AWS_FOUNDATIONS:1.5': 'partial' });
  });
});

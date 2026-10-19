import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { FRAMEWORK_NAMES, assertSanitizedValue } from './map';
import type {
  ChangelogEntry,
  PostureState,
  PublishableResponse,
  TrustControlStatus,
} from './types';

export const CHANGELOG_LIMIT = 20;
const FETCH_TIMEOUT_MS = 10_000;

const NAMES: Record<string, string> = FRAMEWORK_NAMES;

const ANSWER: Record<'PASS' | 'FAIL', TrustControlStatus> = {
  PASS: 'implemented',
  FAIL: 'partial',
};

/** `${framework}:${requirement}` → the answer the page publishes. */
export function currentPosture(response: PublishableResponse): Record<string, TrustControlStatus> {
  const posture: Record<string, TrustControlStatus> = {};
  for (const requirement of response.requirements) {
    posture[`CIS_AWS_FOUNDATIONS:${requirement.requirement}`] = ANSWER[requirement.status];
  }
  for (const requirement of response.mappedFrameworks ?? []) {
    posture[`${requirement.framework}:${requirement.requirement}`] = ANSWER[requirement.status];
  }
  return posture;
}

/** Transitions between two publishes, in stable key order. */
export function diffPosture(
  previous: Record<string, TrustControlStatus> | null,
  current: Record<string, TrustControlStatus>,
  date: string
): ChangelogEntry[] {
  if (!previous) return [];
  const entries: ChangelogEntry[] = [];
  for (const key of Object.keys(current).sort()) {
    const [framework, requirement] = splitKey(key);
    const label = `${NAMES[framework] ?? framework} ${requirement}`;
    const before = previous[key];
    if (before === undefined) {
      entries.push({
        date,
        title: `${label} is now published`,
        description: `Current answer: ${current[key]}.`,
      });
    } else if (before !== current[key]) {
      entries.push({
        date,
        title: `${label} moved to ${current[key]}`,
        description: `Previously ${before}.`,
      });
    }
  }
  for (const key of Object.keys(previous).sort()) {
    if (key in current) continue;
    const [framework, requirement] = splitKey(key);
    entries.push({
      date,
      title: `${NAMES[framework] ?? framework} ${requirement} is no longer published`,
      description:
        'It left the publishable set; the page shows only currently publishable requirements.',
    });
  }
  return entries;
}

function splitKey(key: string): [string, string] {
  const index = key.indexOf(':');
  return index === -1 ? [key, ''] : [key.slice(0, index), key.slice(index + 1)];
}

export interface LoadStateOptions {
  outDir: string;
  publicUrl?: string;
  fetchImpl?: typeof fetch;
  log?: (line: string) => void;
}

/**
 * The previous publish's state, from the local output directory first and from
 * the deployed site's static posture-state.json second. Unreadable or malformed
 * state means "no previous publish": no changelog, never an error.
 */
export async function loadPreviousState(options: LoadStateOptions): Promise<PostureState | null> {
  const log = options.log ?? (() => undefined);
  const local = join(options.outDir, 'posture-state.json');
  if (existsSync(local)) {
    const state = parseState(readFileSync(local, 'utf8'));
    if (state) return state;
    log('ignoring unreadable local posture-state.json');
  }

  const publicUrl = options.publicUrl?.trim().replace(/\/+$/, '');
  if (!publicUrl) return null;
  const fetchImpl = options.fetchImpl ?? fetch;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const response = await fetchImpl(`${publicUrl}/posture-state.json`, {
      headers: { accept: 'application/json' },
      signal: controller.signal,
    });
    if (!response.ok) {
      log(
        `previous posture-state.json unavailable (HTTP ${response.status}); changelog starts empty`
      );
      return null;
    }
    const state = parseState(await response.text());
    if (!state) log('ignoring malformed public posture-state.json');
    return state;
  } catch (error) {
    log(`previous posture-state.json unreadable; changelog starts empty: ${String(error)}`);
    return null;
  } finally {
    clearTimeout(timer);
  }
}

export function parseState(contents: string): PostureState | null {
  try {
    const parsed = JSON.parse(contents) as Partial<PostureState>;
    if (
      !parsed ||
      typeof parsed !== 'object' ||
      !parsed.posture ||
      typeof parsed.posture !== 'object'
    ) {
      return null;
    }
    const changelog = Array.isArray(parsed.changelog)
      ? parsed.changelog
          .filter(
            (entry): entry is ChangelogEntry =>
              !!entry &&
              typeof entry.date === 'string' &&
              typeof entry.title === 'string' &&
              (entry.description === undefined || typeof entry.description === 'string')
          )
          .slice(0, CHANGELOG_LIMIT)
      : [];
    return {
      updatedAt: typeof parsed.updatedAt === 'string' ? parsed.updatedAt : '',
      posture: parsed.posture as Record<string, TrustControlStatus>,
      changelog,
    };
  } catch {
    return null;
  }
}

/** Carries the rolling changelog forward, newest first. */
export function nextState(
  previous: PostureState | null,
  posture: Record<string, TrustControlStatus>,
  changes: ChangelogEntry[],
  now: Date
): PostureState {
  const state: PostureState = {
    updatedAt: now.toISOString(),
    posture,
    changelog: [...changes, ...(previous?.changelog ?? [])].slice(0, CHANGELOG_LIMIT),
  };
  assertSanitizedValue(state);
  return state;
}

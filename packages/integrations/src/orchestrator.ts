import type { IssueActionSink, IssueLike, RuleLike, ExternalRef } from './types';
import { getSink } from './types';
import './sinks/sns-sink';
import './sinks/slack-sink';

export interface EmitResult {
  externalRefs: ExternalRef[];
  errors: string[];
}

export class IssueIntegrationsOrchestrator {
  private sinks: IssueActionSink[];

  constructor() {
    const configured = (process.env.ISSUE_SINKS || '')
      .split(',')
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean);

    const deduped = [...new Set(configured)];
    this.sinks = deduped
      .map((name) => getSink(name))
      .filter((sink): sink is IssueActionSink => sink !== null);
  }

  async emit(issue: IssueLike, rule: RuleLike): Promise<ExternalRef[]> {
    if (this.sinks.length === 0) return [];

    const refs: ExternalRef[] = [];
    const errors: string[] = [];

    for (const sink of this.sinks) {
      try {
        const ref = await sink.emit(issue, rule);
        if (ref) refs.push(ref);
      } catch (e) {
        errors.push(`${sink.system}: ${e instanceof Error ? e.message : String(e)}`);
      }
    }

    return refs;
  }

  async healthCheck(): Promise<Record<string, boolean>> {
    const results: Record<string, boolean> = {};
    for (const sink of this.sinks) {
      try {
        results[sink.system] = await sink.healthCheck();
      } catch {
        results[sink.system] = false;
      }
    }
    return results;
  }

  get configuredSinks(): string[] {
    return this.sinks.map((s) => s.system);
  }
}

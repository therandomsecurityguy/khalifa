import { getControlById, type ComplianceControlStatus } from './compliance-types';
import {
  FRAMEWORK_CITATIONS,
  aggregateMappedStatus,
  citationsByFramework,
  citationsForControl,
  isMappedFramework,
} from './framework-citations';

describe('FRAMEWORK_CITATIONS', () => {
  it('pins the reviewed requirement list', () => {
    expect(FRAMEWORK_CITATIONS.map((c) => `${c.framework}:${c.requirement}`)).toEqual([
      'SOC2:CC6.1',
      'SOC2:CC6.2',
      'SOC2:CC6.3',
      'SOC2:CC6.6',
      'SOC2:CC6.7',
      'SOC2:CC7.1',
      'SOC2:CC7.2',
      'SOC2:CC7.3',
      'SOC2:CC9.1',
      'ISO27001:A.5.15',
      'ISO27001:A.5.16',
      'ISO27001:A.5.17',
      'ISO27001:A.5.23',
      'ISO27001:A.5.33',
      'ISO27001:A.8.2',
      'ISO27001:A.8.3',
      'ISO27001:A.8.5',
      'ISO27001:A.8.8',
      'ISO27001:A.8.9',
      'ISO27001:A.8.12',
      'ISO27001:A.8.13',
      'ISO27001:A.8.15',
      'ISO27001:A.8.16',
      'ISO27001:A.8.20',
      'ISO27001:A.8.21',
      'ISO27001:A.8.24',
    ]);
  });

  it('cites only canonical controls that exist', () => {
    for (const citation of FRAMEWORK_CITATIONS) {
      expect(citation.controls.length).toBeGreaterThan(0);
      expect(new Set(citation.controls).size).toBe(citation.controls.length);
      for (const id of citation.controls) {
        expect(getControlById(id)).toBeDefined();
      }
    }
  });

  it('records reviewed reasoning and display fields for every requirement', () => {
    for (const citation of FRAMEWORK_CITATIONS) {
      expect(citation.title.trim().length).toBeGreaterThan(0);
      expect(citation.description.trim().length).toBeGreaterThan(0);
      expect(citation.section.trim().length).toBeGreaterThan(0);
      expect(citation.why.trim().length).toBeGreaterThan(0);
    }
  });

  it('keeps requirement ids unique per framework', () => {
    const keys = FRAMEWORK_CITATIONS.map((c) => `${c.framework}:${c.requirement}`);
    expect(new Set(keys).size).toBe(keys.length);
  });

  it('classifies pluggable frameworks correctly', () => {
    expect(isMappedFramework('SOC2')).toBe(true);
    expect(isMappedFramework('ISO27001')).toBe(true);
    expect(isMappedFramework('CIS_AWS_FOUNDATIONS')).toBe(false);
    expect(isMappedFramework('KHALIFA_BASELINE')).toBe(false);
  });

  it('filters by framework and resolves the reverse index', () => {
    expect(citationsByFramework('SOC2')).toHaveLength(9);
    expect(citationsByFramework('ISO27001')).toHaveLength(17);
    const citing = citationsForControl('1.5').map((c) => `${c.framework}:${c.requirement}`);
    expect(citing).toContain('SOC2:CC6.1');
    expect(citing).toContain('ISO27001:A.5.17');
  });
});

describe('aggregateMappedStatus', () => {
  const status = (...s: ComplianceControlStatus[]) => aggregateMappedStatus(s);

  it('fails when any mapped control fails', () => {
    expect(status('PASS', 'FAIL', 'PASS')).toBe('FAIL');
    expect(status('FAIL')).toBe('FAIL');
  });

  it('passes only when every mapped control passes', () => {
    expect(status('PASS', 'PASS')).toBe('PASS');
  });

  it('treats fully not-applicable requirements as not applicable', () => {
    expect(status('NOT_APPLICABLE', 'NOT_APPLICABLE')).toBe('NOT_APPLICABLE');
  });

  it('keeps manual or unevaluated controls from looking like a pass', () => {
    expect(status('PASS', 'MANUAL')).toBe('NOT_EVALUATED');
    expect(status('PASS', 'NOT_EVALUATED')).toBe('NOT_EVALUATED');
  });

  it('is unevaluated without any mapped status', () => {
    expect(status()).toBe('NOT_EVALUATED');
  });
});

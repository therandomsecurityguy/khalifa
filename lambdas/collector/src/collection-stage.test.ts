import { collectServiceStage, mergeDuplicateNodes, summarizeCoverage } from '../index';

describe('collectServiceStage', () => {
  it('records successful service coverage', async () => {
    const data = { nodes: [{ id: 'node', label: 'Resource', properties: {} }], edges: [] };

    const result = await collectServiceStage('ec2', true, async () => data);

    expect(result.data).toBe(data);
    expect(result.coverage).toMatchObject({
      service: 'ec2',
      status: 'SUCCEEDED',
      nodes: 1,
      edges: 0,
    });
  });

  it('does not call stages that are intentionally skipped', async () => {
    const operation = jest.fn();

    const result = await collectServiceStage('iam', false, operation);

    expect(operation).not.toHaveBeenCalled();
    expect(result.coverage.status).toBe('SKIPPED');
  });

  it('records access failures without rejecting the account run', async () => {
    const error = Object.assign(new Error('denied'), {
      name: 'AccessDeniedException',
      $metadata: { httpStatusCode: 403 },
    });

    const result = await collectServiceStage('kms', true, async () => {
      throw error;
    });

    expect(result.data).toEqual({ nodes: [], edges: [] });
    expect(result.coverage).toMatchObject({
      service: 'kms',
      status: 'FAILED',
      failureType: 'ACCESS_DENIED',
      error: 'denied',
    });
  });
});

describe('summarizeCoverage', () => {
  it('marks only throttled, timed-out, and transient failures as retryable', () => {
    const at = '2026-09-17T00:00:00.000Z';
    const record = (service: string, status: 'SUCCEEDED' | 'FAILED', failureType?: string) => ({
      service,
      status,
      completedAt: at,
      nodes: 0,
      edges: 0,
      failureType,
    });

    expect(
      summarizeCoverage([
        record('iam', 'SUCCEEDED'),
        record('s3', 'FAILED', 'ACCESS_DENIED'),
        record('network', 'FAILED', 'ERROR'),
        record('ec2-instances', 'FAILED', 'THROTTLED'),
        record('rds', 'FAILED', 'TIMEOUT'),
        record('eks', 'FAILED', 'TRANSIENT'),
      ])
    ).toEqual({
      failedServices: ['s3', 'network', 'ec2-instances', 'rds', 'eks'],
      retryableServices: ['ec2-instances', 'rds', 'eks'],
    });
  });
});

describe('mergeDuplicateNodes', () => {
  it('merges nodes emitted by more than one stage, later properties winning', () => {
    const merged = mergeDuplicateNodes([
      {
        id: 'arn:aws:iam::111122223333:user/a',
        label: 'IamUser',
        properties: { name: 'a', mfa_enabled: false },
      },
      { id: 'arn:aws:s3:::bucket', label: 'S3Bucket', properties: {} },
      {
        id: 'arn:aws:iam::111122223333:user/a',
        label: 'IamUser',
        properties: { mfa_enabled: true, password_enabled: true },
      },
    ]);

    expect(merged).toEqual([
      {
        id: 'arn:aws:iam::111122223333:user/a',
        label: 'IamUser',
        properties: { name: 'a', mfa_enabled: true, password_enabled: true },
      },
      { id: 'arn:aws:s3:::bucket', label: 'S3Bucket', properties: {} },
    ]);
  });

  it('does not let a later undefined/null erase a collected property', () => {
    const merged = mergeDuplicateNodes([
      {
        id: 'arn:aws:iam::111122223333:user/a',
        label: 'IamUser',
        properties: { name: 'a', mfa_enabled: true, create_date: '2020-01-01T00:00:00.000Z' },
      },
      {
        id: 'arn:aws:iam::111122223333:user/a',
        label: 'IamUser',
        properties: { mfa_enabled: undefined, create_date: null, password_enabled: true },
      },
    ]);

    expect(merged).toHaveLength(1);
    expect(merged[0].properties).toEqual({
      name: 'a',
      mfa_enabled: true,
      create_date: '2020-01-01T00:00:00.000Z',
      password_enabled: true,
    });
  });

  it('still lets a later defined value override an earlier one', () => {
    const merged = mergeDuplicateNodes([
      { id: 'x', label: 'IamUser', properties: { mfa_enabled: false } },
      { id: 'x', label: 'IamUser', properties: { mfa_enabled: true } },
    ]);

    expect(merged[0].properties.mfa_enabled).toBe(true);
  });
});

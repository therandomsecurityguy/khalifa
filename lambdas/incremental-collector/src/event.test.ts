import { requireApprovedEventTarget } from '../index';

const scope = {
  accountIds: new Set(['111122223333']),
  regions: new Set(['us-west-2']),
};

const event = {
  account: '111122223333',
  region: 'us-west-2',
  source: 'aws.ec2',
  'detail-type': 'AWS API Call via CloudTrail',
  detail: {
    eventSource: 'ec2.amazonaws.com',
    awsRegion: 'us-west-2',
    recipientAccountId: '111122223333',
    userIdentity: { accountId: '999900001111' },
  },
};

describe('incremental event scope', () => {
  it('uses the approved EventBridge account instead of caller identity', () => {
    expect(requireApprovedEventTarget(event, scope)).toMatchObject({
      accountId: '111122223333',
      region: 'us-west-2',
    });
  });

  it('rejects accounts and Regions outside the approved scope', () => {
    expect(() => requireApprovedEventTarget({ ...event, account: '999900001111' }, scope)).toThrow(
      'Event account is outside the approved collection scope'
    );
    expect(() => requireApprovedEventTarget({ ...event, region: 'us-east-1' }, scope)).toThrow(
      'Event Region is outside the approved collection scope'
    );
  });

  it('rejects malformed and inconsistent event envelopes', () => {
    expect(() => requireApprovedEventTarget(event.detail, scope)).toThrow(
      'Invalid EventBridge event'
    );
    expect(() =>
      requireApprovedEventTarget(
        { ...event, detail: { ...event.detail, recipientAccountId: '999900001111' } },
        scope
      )
    ).toThrow('Event account does not match its CloudTrail detail');
  });
});

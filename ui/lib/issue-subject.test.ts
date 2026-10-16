import type { Issue } from '@/types';
import { issueSubject } from './issue-subject';

const issue = (resourcesInvolved: Issue['resourcesInvolved'], metadata = {}): Issue =>
  ({ resourcesInvolved, metadata }) as unknown as Issue;
const names = new Map([['111122223333', 'inference-prod']]);

describe('issueSubject', () => {
  it('names a grouped issue by its resource, account and finding count', () => {
    const host = 'arn:aws:ec2:us-west-2:111122223333:instance/i-035b74ca';
    const finding = 'arn:aws:securityhub:us-west-2:111122223333:finding/f1';
    expect(
      issueSubject(
        issue(
          [
            { resourceId: host, resourceType: 'Ec2Instance' },
            { resourceId: finding, resourceType: 'SecurityHubFinding' },
          ],
          { matchCount: 162 }
        ),
        names
      )
    ).toEqual({
      name: 'i-035b74ca',
      type: 'EC2 instance',
      account: 'inference-prod',
      matches: '162 findings',
    });
  });

  it('prefers the recorded name, finds the account on another resource, and skips a single match', () => {
    expect(
      issueSubject(
        issue([
          {
            resourceId: 'arn:aws:s3:::payments-exports',
            resourceType: 'S3Bucket',
            resourceName: 'payments-exports',
          },
          { resourceId: 'arn:aws:iam::999988887777:role/app', resourceType: 'IamRole' },
        ]),
        names
      )
    ).toMatchObject({ name: 'payments-exports', account: '999988887777', matches: null });
  });

  it('returns null when an issue records no resource', () => {
    expect(issueSubject(issue([]), names)).toBeNull();
  });
});

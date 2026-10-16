import { render, screen } from '@testing-library/react';
import { getControlDetails, type ComplianceControlDetail } from '@/lib/api';
import ControlDetailPage from './page';

jest.mock('next/navigation', () => ({
  useParams: () => ({ framework: 'SOC2', controlId: 'CC9.1' }),
}));
jest.mock('@/lib/api', () => ({
  ...jest.requireActual('@/lib/api'),
  getControlDetails: jest.fn(),
}));

const mocked = getControlDetails as jest.MockedFunction<typeof getControlDetails>;

function detail(overrides: Partial<ComplianceControlDetail> = {}): ComplianceControlDetail {
  return {
    id: 'CC9.1',
    title: 'Availability is protected with backup and durability controls',
    section: 'Availability',
    severity: 'high',
    automated: true,
    status: 'FAIL',
    framework: 'SOC2',
    lastEvaluated: '2026-10-16T00:00:00.000Z',
    description: 'Backups and deletion protection.',
    remediationHint: 'Address the mapped controls.',
    evidenceRequirements: [],
    evidence: [],
    relatedIssues: [],
    ...overrides,
  };
}

describe('ControlDetailPage mapped frameworks', () => {
  beforeEach(() => jest.clearAllMocks());

  it('links a mapped requirement to the canonical controls that evidence it', async () => {
    mocked.mockResolvedValue(
      detail({
        mappedControls: [
          { controlId: 'KH-2.8', framework: 'KHALIFA_BASELINE', status: 'FAIL', issues: ['3'] },
          { controlId: 'KH-2.10', framework: 'KHALIFA_BASELINE', status: 'PASS', issues: [] },
        ],
      })
    );

    render(<ControlDetailPage />);

    await screen.findByText('Evidenced by');
    const failing = screen.getByRole('link', { name: /Khalifa Baseline · KH-2\.8/ });
    expect(failing).toHaveAttribute('href', '/compliance/KHALIFA_BASELINE/controls/KH-2.8');
    expect(screen.getByRole('link', { name: /KH-2\.10/ })).toHaveAttribute(
      'href',
      '/compliance/KHALIFA_BASELINE/controls/KH-2.10'
    );
    expect(screen.getByText(/passes only while every mapped control passes/)).toBeInTheDocument();
  });

  it('tells a canonical control which framework requirements cite it', async () => {
    mocked.mockResolvedValue(
      detail({
        id: '1.5',
        title: 'Root MFA',
        framework: 'CIS_AWS_FOUNDATIONS',
        status: 'PASS',
        mappedControls: undefined,
        citedBy: [
          { framework: 'SOC2', requirement: 'CC6.1', title: 'Logical access' },
          { framework: 'ISO27001', requirement: 'A.5.17', title: 'Authentication information' },
        ],
      })
    );

    render(<ControlDetailPage />);

    await screen.findByText('Cited by framework requirements');
    expect(screen.getByRole('link', { name: /CC6\.1/ })).toHaveAttribute(
      'href',
      '/compliance/SOC2/controls/CC6.1'
    );
    expect(screen.getByRole('link', { name: /A\.5\.17/ })).toHaveAttribute(
      'href',
      '/compliance/ISO27001/controls/A.5.17'
    );
    expect(screen.queryByText('Evidenced by')).not.toBeInTheDocument();
  });
});

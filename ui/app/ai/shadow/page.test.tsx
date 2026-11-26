import { render, screen } from '@testing-library/react';
import { getAccounts, getAiShadow } from '@/lib/api';
import type { ShadowAiResponse } from '@/types';
import ShadowAiPage from './page';

jest.mock('@/lib/api', () => ({
  ...jest.requireActual('@/lib/api'),
  getAccounts: jest.fn(),
  getAiShadow: jest.fn(),
}));

function response(overrides: Partial<ShadowAiResponse> = {}): ShadowAiResponse {
  return {
    anomalies: [
      {
        arn: 'arn:aws:khalifa:anomaly:111122223333:cloudtrail-anomaly/SHADOW_AI_USAGE/abc',
        principalArn: 'arn:aws:sts::111122223333:assumed-role/MysteryTeam',
        accountId: '111122223333',
        sourceIp: '203.0.113.11',
        eventCount: 3,
        firstSeen: '2026-11-24T08:00:00Z',
        lastSeen: '2026-11-24T09:00:00Z',
        detail: 'CreateNotebookInstance, ListAgents',
        observedAt: '2026-11-24T10:00:00Z',
      },
    ],
    coverage: {
      plane: 'management',
      windowDays: 7,
      detail:
        'Bedrock and SageMaker management-plane API calls recorded in CloudTrail. Model-invocation (data-plane) events — InvokeModel, InvokeAgent, InvokeEndpoint — are visible only when CloudTrail data events are enabled; Khalifa cannot verify that setting, so treat this as the management-plane view.',
      lastAnomalyObservedAt: '2026-11-24T10:00:00Z',
      freshness: 'aging',
    },
    ...overrides,
  };
}

describe('ShadowAiPage', () => {
  beforeEach(() => {
    (getAccounts as jest.Mock).mockResolvedValue({
      accounts: [{ id: '111122223333', name: 'payments-prod' }],
    });
    (getAiShadow as jest.Mock).mockReset().mockResolvedValue(response());
  });

  it('renders the coverage statement, account name, and the anomaly row', async () => {
    render(<ShadowAiPage />);

    expect(await screen.findByRole('heading', { name: 'Anomalies (1)' })).toBeInTheDocument();
    expect(screen.getByText(/data events are enabled/)).toBeInTheDocument();
    expect(screen.getByText('payments-prod')).toBeInTheDocument();
    expect(
      screen.getByText('arn:aws:sts::111122223333:assumed-role/MysteryTeam')
    ).toBeInTheDocument();
    expect(screen.getByText('CreateNotebookInstance, ListAgents')).toBeInTheDocument();
    expect(screen.getByText(/more than two days old/)).toBeInTheDocument();
  });

  it('keeps the management-plane caveat on an empty list', async () => {
    (getAiShadow as jest.Mock).mockResolvedValue(
      response({
        anomalies: [],
        coverage: {
          ...response().coverage,
          lastAnomalyObservedAt: null,
          freshness: 'unknown',
        },
      })
    );

    render(<ShadowAiPage />);

    expect(await screen.findByText('No shadow-AI usage recorded')).toBeInTheDocument();
    expect(screen.getByText(/not proof that no AI usage exists/)).toBeInTheDocument();
    expect(screen.getByText(/unknown freshness, not a clean estate/)).toBeInTheDocument();
  });
});

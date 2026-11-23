import { render, screen } from '@testing-library/react';
import { getAccounts, getAiInventory } from '@/lib/api';
import type { AiInventoryItem, AiInventorySection } from '@/types';
import AiInventoryPage from './page';

jest.mock('@/lib/api', () => ({
  ...jest.requireActual('@/lib/api'),
  getAccounts: jest.fn(),
  getAiInventory: jest.fn(),
}));

function item(overrides: Partial<AiInventoryItem>): AiInventoryItem {
  return {
    id: 'agent-1',
    arn: 'arn:aws:bedrock:us-west-2:111122223333:agent/agent-1',
    name: 'support-agent',
    status: 'PREPARED',
    account_id: '111122223333',
    region: 'us-west-2',
    platform: 'bedrock',
    role_arn: 'arn:aws:iam::111122223333:role/agent-role',
    facts: { guardrail_configured: true, foundation_model: 'anthropic.claude' },
    ...overrides,
  };
}

function section(overrides: Partial<AiInventorySection>): AiInventorySection {
  return {
    type: 'agents',
    label: 'AiAgent',
    count: 1,
    items: [],
    truncated: false,
    ...overrides,
  };
}

describe('AiInventoryPage', () => {
  beforeEach(() => {
    (getAccounts as jest.Mock).mockResolvedValue({
      accounts: [{ id: '111122223333', name: 'payments-prod' }],
    });
    (getAiInventory as jest.Mock).mockReset().mockResolvedValue({
      types: [
        section({ type: 'agents', count: 2, items: [item({})], truncated: true }),
        section({ type: 'guardrails', label: 'AiGuardrail', count: 0, items: [] }),
      ],
    });
  });

  it('renders sections with counts, account names, facts, and agent links', async () => {
    render(<AiInventoryPage />);

    expect(await screen.findByRole('heading', { name: 'AI agents (2)' })).toBeInTheDocument();
    expect(screen.getByText(/Showing the first 1 of 2\./)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'support-agent' })).toHaveAttribute(
      'href',
      '/ai/detail?arn=' + encodeURIComponent('arn:aws:bedrock:us-west-2:111122223333:agent/agent-1')
    );
    expect(screen.getByText('payments-prod')).toBeInTheDocument();
    expect(screen.getByText(/guardrail configured: yes/)).toBeInTheDocument();

    expect(screen.getByRole('heading', { name: 'Guardrails (0)' })).toBeInTheDocument();
    expect(screen.getByText('No guardrails collected')).toBeInTheDocument();
  });

  it('links non-agent items to the resource explorer', async () => {
    const notebookArn = 'arn:aws:sagemaker:us-west-2:111122223333:notebook-instance/lab';
    (getAiInventory as jest.Mock).mockResolvedValue({
      types: [
        section({
          type: 'notebooks',
          label: 'AiNotebook',
          items: [
            item({
              arn: notebookArn,
              name: 'lab',
              platform: null,
              facts: { root_access: 'Disabled' },
            }),
          ],
        }),
      ],
    });

    render(<AiInventoryPage />);

    expect(await screen.findByRole('link', { name: 'lab' })).toHaveAttribute(
      'href',
      '/resources?arn=' + encodeURIComponent(notebookArn)
    );
  });

  it('shows a retryable error state when the inventory read fails', async () => {
    (getAiInventory as jest.Mock).mockRejectedValue(new Error('nope'));

    render(<AiInventoryPage />);

    expect(await screen.findByText('nope')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: /AI agents/ })).toBeNull();
  });
});

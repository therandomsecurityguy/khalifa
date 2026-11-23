import { render, screen } from '@testing-library/react';
import { ApiError, getAiAgent } from '@/lib/api';
import type { AiAgentDetail } from '@/types';
import AiAgentDetailPage from './page';

let search = '';
jest.mock('next/navigation', () => ({ useSearchParams: () => new URLSearchParams(search) }));
jest.mock('@/lib/api', () => ({
  ...jest.requireActual('@/lib/api'),
  getAiAgent: jest.fn(),
}));

const ARN = 'arn:aws:bedrock:us-west-2:111122223333:agent/agent-1';
const ROLE_ARN = 'arn:aws:iam::111122223333:role/agent-role';
const KB_ARN = 'arn:aws:bedrock:us-west-2:111122223333:knowledge-base/kb-1';
const GUARDRAIL_ARN = 'arn:aws:bedrock:us-west-2:111122223333:guardrail/gr-1';
const LAMBDA_ARN = 'arn:aws:lambda:us-west-2:111122223333:function:tool';

const detail: AiAgentDetail = {
  agent: {
    id: ARN,
    label: 'AiAgent',
    properties: {
      name: 'support-agent',
      platform: 'bedrock',
      status: 'PREPARED',
      guardrail_configured: true,
      has_instruction: true,
      foundation_model: 'anthropic.claude',
    },
  },
  role: { id: ROLE_ARN, label: 'IamRole', properties: { name: 'agent-role' } },
  knowledgeBases: [{ id: KB_ARN, label: 'AiKnowledgeBase', properties: { name: 'kb' } }],
  guardrail: { id: GUARDRAIL_ARN, label: 'AiGuardrail', properties: { name: 'strict' } },
  tools: [{ id: LAMBDA_ARN, label: 'LambdaFunction', properties: { name: 'tool' } }],
  model: null,
  issues: [
    {
      id: 'RULE-037-v2-abc',
      ruleId: 'RULE-037',
      severity: 'high',
      status: 'open',
      resourcesInvolved: [],
      pathSummary: [],
      riskScore: 82,
      createdAt: '2026-11-01T00:00:00.000Z',
      updatedAt: '2026-11-01T00:00:00.000Z',
      owningTeam: 'cloud-security',
      remediationHint: '',
      metadata: {},
    },
  ],
};

describe('AiAgentDetailPage', () => {
  beforeEach(() => {
    search = `arn=${encodeURIComponent(ARN)}`;
    (getAiAgent as jest.Mock).mockReset().mockResolvedValue(detail);
  });

  it('shows the agent with its role, knowledge bases, tools, guardrail, and issues', async () => {
    render(<AiAgentDetailPage />);

    expect(await screen.findByRole('heading', { name: 'support-agent' })).toBeInTheDocument();
    expect(getAiAgent).toHaveBeenCalledWith(ARN, expect.anything());
    expect(screen.getByRole('link', { name: 'agent-role' })).toHaveAttribute(
      'href',
      '/resources?arn=' + encodeURIComponent(ROLE_ARN)
    );
    expect(screen.getByRole('link', { name: 'kb' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'tool' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'strict' })).toBeInTheDocument();
    expect(screen.getByText('Set (never stored)')).toBeInTheDocument();
    expect(screen.getByText('RULE-037')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'View issue →' })).toHaveAttribute(
      'href',
      '/issues/' + encodeURIComponent('RULE-037-v2-abc')
    );
    expect(screen.getByRole('link', { name: 'Attack paths to this agent →' })).toHaveAttribute(
      'href',
      `/attack-paths?from=any&to=resource&toResource=${encodeURIComponent(ARN)}&hops=4`
    );
  });

  it('refuses a link that is not an agent ARN without calling the API', async () => {
    search = `arn=${encodeURIComponent('arn:aws:iam::111122223333:role/admin')}`;

    render(<AiAgentDetailPage />);

    expect(
      await screen.findByText(/does not name a Bedrock agent or AgentCore runtime/)
    ).toBeInTheDocument();
    expect(getAiAgent).not.toHaveBeenCalled();
  });

  it('renders a not-found state when the graph has no such agent', async () => {
    (getAiAgent as jest.Mock).mockRejectedValue(new ApiError(404, 'AI agent not found'));

    render(<AiAgentDetailPage />);

    expect(
      await screen.findByText('No AI agent with that ARN is in the collected graph.')
    ).toBeInTheDocument();
  });
});

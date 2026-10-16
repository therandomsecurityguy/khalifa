import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { GraphVertex } from '@/types';
import { AttackGraph } from './attack-graph';

const external: GraphVertex = {
  id: 'arn:aws:khalifa:external-account:999988887777',
  label: 'ExternalAccount',
  properties: { account_id: '999988887777', name: 'Account 999988887777' },
};
const role: GraphVertex = {
  id: 'arn:aws:iam::111122223333:role/FlanDiscoveryRole',
  label: 'IamRole',
  properties: {
    account_id: '111122223333',
    name: 'FlanDiscoveryRole',
    has_cross_account_trust: true,
  },
};
const policy: GraphVertex = {
  id: 'arn:aws:iam::111122223333:policy/FlanDiscoveryReadOnly',
  label: 'IamPolicyDocument',
  properties: { account_id: '111122223333', name: 'FlanDiscoveryReadOnly' },
};
const statement: GraphVertex = {
  id: 'arn:aws:iam::111122223333:policy/FlanDiscoveryReadOnly/0',
  label: 'IamPolicyStatement',
  properties: {
    account_id: '111122223333',
    name: 'DiscoveryReadOnly',
    has_wildcard_resource: true,
  },
};
const flanPath = {
  nodes: [role, policy, statement],
  edges: [
    { id: 'a', label: 'ATTACHED_TO', from: role.id, to: policy.id },
    { id: 'b', label: 'CONTAINS', from: policy.id, to: statement.id },
  ],
};

describe('AttackGraph', () => {
  it('draws a trust finding from the outside account with named account bands', () => {
    render(
      <AttackGraph
        paths={[flanPath]}
        entries={{ [role.id]: { kind: 'trust', principals: [external] } }}
        accountNames={{ '111122223333': 'prod' }}
        empty="none"
      />
    );

    const graph = screen.getByRole('group', { name: 'Attack path graph' });
    expect(within(graph).getAllByText('External account').length).toBeGreaterThan(0);
    expect(within(graph).getByText('not collected')).toBeInTheDocument();
    expect(within(graph).getByText('prod')).toBeInTheDocument();
    expect(within(graph).getByText('Can assume · Cross-account')).toBeInTheDocument();
    expect(within(graph).queryByText(/Public internet/)).not.toBeInTheDocument();

    // The single path opens on its target: the role, carrying the folded statement.
    const details = screen.getByRole('complementary');
    expect(within(details).getByRole('heading', { name: 'FlanDiscoveryRole' })).toBeInTheDocument();
    expect(within(details).getByText('Wildcard resource')).toBeInTheDocument();
    expect(within(details).getByText('DiscoveryReadOnly')).toBeInTheDocument();
    expect(within(details).getByText('Policy FlanDiscoveryReadOnly')).toBeInTheDocument();
    expect(within(details).getByText('prod · 111122223333')).toBeInTheDocument();
  });

  it('opens merged paths on the overview and focuses one resource on click', async () => {
    const other: GraphVertex = {
      id: 'arn:aws:iam::111122223333:role/Other',
      label: 'IamRole',
      properties: { account_id: '111122223333', name: 'Other' },
    };
    render(
      <AttackGraph
        paths={[flanPath, { nodes: [other], edges: [] }]}
        entries={{ [role.id]: { kind: 'trust', principals: [external] } }}
        empty="none"
      />
    );

    const details = screen.getByRole('complementary');
    expect(within(details).getByText('Overview')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: /IAM role FlanDiscoveryRole/ }));
    expect(within(details).getByRole('heading', { name: 'FlanDiscoveryRole' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /IAM role Other/ })).toHaveAttribute(
      'opacity',
      '0.18'
    );

    await userEvent.click(within(details).getByRole('button', { name: 'Show all paths' }));
    expect(within(details).getByText('Overview')).toBeInTheDocument();
  });

  it('shows the empty state when there is no path', () => {
    render(<AttackGraph paths={[]} empty="No attack path recorded for this issue." />);
    expect(screen.getByText('No attack path recorded for this issue.')).toBeInTheDocument();
  });

  it('draws a Deny grant as no access, lists steps for screen readers, and clears on Escape', async () => {
    const bucket: GraphVertex = {
      id: 'arn:aws:s3:::data',
      label: 'S3Bucket',
      properties: { account_id: '111122223333', name: 'data' },
    };
    const deny: GraphVertex = {
      ...statement,
      properties: { ...statement.properties, effect: 'Deny' },
    };
    const other: GraphVertex = {
      id: 'arn:aws:iam::111122223333:role/Other',
      label: 'IamRole',
      properties: { account_id: '111122223333', name: 'Other' },
    };
    render(
      <AttackGraph
        paths={[
          {
            nodes: [role, policy, deny, bucket],
            edges: [...flanPath.edges, { id: 'c', label: 'GRANTS', from: deny.id, to: bucket.id }],
          },
          { nodes: [other], edges: [] },
        ]}
        empty="none"
      />
    );

    expect(screen.getByText('Deny (no access)')).toBeInTheDocument();
    expect(
      within(screen.getByRole('list', { name: 'Path steps' })).getByText(/FlanDiscoveryRole denies/)
    ).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: /S3 bucket data/ }));
    expect(
      within(screen.getByRole('complementary')).getByRole('heading', { name: 'data' })
    ).toBeInTheDocument();
    await userEvent.keyboard('{Escape}');
    expect(within(screen.getByRole('complementary')).getByText('Overview')).toBeInTheDocument();
  });

  it('lists choke points and selects one on click', async () => {
    const other: GraphVertex = {
      id: 'arn:aws:iam::111122223333:role/Other',
      label: 'IamRole',
      properties: { account_id: '111122223333', name: 'Other' },
    };
    const bucket: GraphVertex = {
      id: 'arn:aws:s3:::data',
      label: 'S3Bucket',
      properties: { account_id: '111122223333', name: 'data' },
    };
    const hop = (from: GraphVertex, to: GraphVertex) => ({
      id: `${from.id}>${to.id}`,
      label: 'GRANTS',
      from: from.id,
      to: to.id,
    });
    render(
      <AttackGraph
        paths={[
          {
            nodes: [external, role, bucket],
            edges: [hop(external, role), hop(role, bucket)],
            score: 80,
            severity: 'high',
          },
          {
            nodes: [external, other, bucket],
            edges: [hop(external, other), hop(other, bucket)],
            score: 30,
            severity: 'low',
          },
          {
            nodes: [external, role, other],
            edges: [hop(external, role), hop(role, other)],
            score: 40,
            severity: 'medium',
          },
        ]}
        empty="none"
      />
    );

    const details = screen.getByRole('complementary');
    expect(within(details).getByText('Choke points - fix first')).toBeInTheDocument();
    const first = within(details).getAllByRole('button', { name: /of 3 paths/ })[0];
    expect(first).toHaveTextContent('FlanDiscoveryRole');
    expect(first).toHaveTextContent('2/3');
    expect(within(details).getAllByText('high').length).toBeGreaterThan(0);

    await userEvent.click(first);
    expect(within(details).getByRole('heading', { name: 'FlanDiscoveryRole' })).toBeInTheDocument();
    expect(within(details).getByText('2 of 3')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /IAM role Other/ })).toHaveAttribute('opacity', '1');
  });

  it('groups identical neighbours, expands them on click, and labels only focused edges', async () => {
    const bucket: GraphVertex = {
      id: 'arn:aws:s3:::data',
      label: 'S3Bucket',
      properties: { account_id: '111122223333', name: 'data' },
    };
    const roles = ['a', 'b'].map((name): GraphVertex => ({
      id: `arn:aws:iam::111122223333:role/${name}`,
      label: 'IamRole',
      properties: { account_id: '111122223333', name },
    }));
    render(
      <AttackGraph
        paths={roles.map((r) => ({
          nodes: [r, bucket],
          edges: [{ id: r.id, label: 'GRANTS', from: r.id, to: bucket.id }],
        }))}
        empty="none"
      />
    );

    const graph = screen.getByRole('group', { name: 'Attack path graph' });
    expect(within(graph).getByText('IAM role ×2')).toBeInTheDocument();
    expect(within(graph).queryByText('Grants')).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: /2 IAM role with the same links/ }));
    expect(screen.getByRole('button', { name: /IAM role a/ })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /IAM role b/ })).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: /IAM role a/ }));
    expect(within(graph).getAllByText('Grants')).toHaveLength(1);

    await userEvent.click(screen.getByRole('button', { name: 'Regroup' }));
    expect(within(graph).getByText('IAM role ×2')).toBeInTheDocument();
  });

  it('lists paths in the order given and shows one alone on click', async () => {
    const other: GraphVertex = {
      id: 'arn:aws:iam::111122223333:role/Other',
      label: 'IamRole',
      properties: { account_id: '111122223333', name: 'Other' },
    };
    const bucket: GraphVertex = {
      id: 'arn:aws:s3:::data',
      label: 'S3Bucket',
      properties: { account_id: '111122223333', name: 'data', data_classification: 'restricted' },
    };
    const hop = (from: GraphVertex, to: GraphVertex) => ({
      id: `${from.id}>${to.id}`,
      label: 'GRANTS',
      from: from.id,
      to: to.id,
    });
    render(
      <AttackGraph
        paths={[
          {
            nodes: [role, bucket],
            edges: [hop(role, bucket)],
            score: 80,
            severity: 'high',
          },
          {
            nodes: [other, bucket],
            edges: [hop(other, bucket)],
            score: 30,
            severity: 'low',
          },
        ]}
        entries={{ [role.id]: { kind: 'trust', principals: [external] } }}
        empty="none"
      />
    );

    const details = screen.getByRole('complementary');
    const rows = within(within(details).getByRole('list', { name: 'Paths' })).getAllByRole(
      'button'
    );
    expect(rows).toHaveLength(2);
    expect(rows[0]).toHaveTextContent('high');
    expect(rows[0]).toHaveTextContent('From an outside account');
    expect(rows[0]).toHaveTextContent('Account 999988887777 → data');
    expect(rows[0]).toHaveTextContent('2 hops · 2 risks');
    expect(rows[1]).toHaveTextContent('low');
    expect(rows[1]).toHaveTextContent('From inside');
    expect(rows[1]).toHaveTextContent('Other → data');
    expect(rows[1]).toHaveTextContent('1 hop · 1 risk');

    await userEvent.click(rows[1]);
    expect(within(details).getByRole('heading', { name: 'Other → data' })).toBeInTheDocument();
    expect(within(details).getByText('Steps')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /IAM role FlanDiscoveryRole/ })).toHaveAttribute(
      'opacity',
      '0.18'
    );
    expect(screen.getByRole('button', { name: /IAM role Other/ })).toHaveAttribute('opacity', '1');

    // A resource picked while a path is shown alone keeps that path in view.
    await userEvent.click(screen.getByRole('button', { name: /S3 bucket data/ }));
    expect(within(details).getByRole('heading', { name: 'data' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /IAM role FlanDiscoveryRole/ })).toHaveAttribute(
      'opacity',
      '0.18'
    );
    await userEvent.click(within(details).getByRole('button', { name: 'Back to path' }));
    expect(within(details).getByRole('heading', { name: 'Other → data' })).toBeInTheDocument();

    await userEvent.click(within(details).getByRole('button', { name: 'Show all paths' }));
    expect(within(details).getByText('Overview')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /IAM role FlanDiscoveryRole/ })).toHaveAttribute(
      'opacity',
      '1'
    );
  });
});

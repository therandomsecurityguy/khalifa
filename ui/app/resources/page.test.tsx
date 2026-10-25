import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import {
  getPropertyValues,
  getResourceLabels,
  getResourceProperties,
  searchResources,
} from '@/lib/api';
import ResourcesPage from './page';

const push = jest.fn();
let mockSearch = '';

jest.mock('next/navigation', () => ({
  useRouter: () => ({ push, replace: jest.fn() }),
  useSearchParams: () => new URLSearchParams(mockSearch),
}));

jest.mock('@/lib/api', () => ({
  ...jest.requireActual('@/lib/api'),
  getPropertyValues: jest.fn(),
  getResourceLabels: jest.fn(),
  getResourceProperties: jest.fn(),
  searchResources: jest.fn(),
}));

const mockedLabels = getResourceLabels as jest.MockedFunction<typeof getResourceLabels>;
const mockedSearch = searchResources as jest.MockedFunction<typeof searchResources>;
const mockedProperties = getResourceProperties as jest.MockedFunction<typeof getResourceProperties>;
const mockedValues = getPropertyValues as jest.MockedFunction<typeof getPropertyValues>;

describe('ResourcesPage search', () => {
  beforeEach(() => {
    mockSearch = '';
    push.mockReset();
    mockedLabels.mockReset().mockResolvedValue({
      labels: [
        { label: 'S3Bucket', count: 1204 },
        { label: 'IamRole', count: 356 },
      ],
    });
    mockedSearch.mockReset().mockResolvedValue({ label: 'IamRole', resources: [] });
    mockedProperties
      .mockReset()
      .mockResolvedValue({ properties: ['account_id', 'is_admin_role', 'name'] });
    mockedValues.mockReset().mockResolvedValue({ values: [], more: false });
  });

  it('offers the labels in the graph with their counts', async () => {
    render(<ResourcesPage />);

    const box = await screen.findByRole('combobox', { name: 'Label' });
    await userEvent.click(box);
    expect(await screen.findByRole('option', { name: 'S3 bucket (1,204)' })).toBeInTheDocument();
    // All labels first, then A to Z by display name.
    expect(
      within(screen.getByRole('listbox', { name: 'Label' }))
        .getAllByRole('option')
        .map((option) => option.getAttribute('aria-label'))
    ).toEqual(['All labels', 'IAM role (356)', 'S3 bucket (1,204)']);

    await userEvent.click(screen.getByRole('option', { name: 'S3 bucket (1,204)' }));
    expect(box).toHaveValue('S3 bucket');
    await userEvent.click(screen.getByRole('button', { name: 'Search' }));
    expect(push).toHaveBeenCalledWith('/resources?label=S3Bucket');
  });

  it('opens on All labels and lists every resource without a filter', async () => {
    mockedSearch.mockResolvedValue({
      label: '*',
      resources: [{ id: 'arn:aws:s3:::logs', label: 'S3Bucket', properties: { name: 'logs' } }],
    });
    render(<ResourcesPage />);

    expect(await screen.findByRole('combobox', { name: 'Label' })).toHaveValue('All labels');
    expect(await screen.findByText('logs')).toBeInTheDocument();
    expect(mockedSearch).toHaveBeenCalledWith('*', undefined, undefined, 50, expect.anything());
    expect(screen.getByRole('button', { name: 'Search' })).toBeEnabled();
  });

  it('says when the property list fails to load and retries on request', async () => {
    mockedProperties
      .mockRejectedValueOnce(new Error('Failed to list properties'))
      .mockResolvedValueOnce({ properties: ['env'] });
    render(<ResourcesPage />);

    expect(await screen.findByText(/Couldn.t load the property list/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByRole('option', { name: 'env' })).toBeInTheDocument();
  });

  it('shows how many are loaded and appends the next page on request', async () => {
    mockSearch = 'label=IamRole';
    const bucket = (name: string) => ({
      id: `arn:aws:s3:::${name}`,
      label: 'S3Bucket',
      properties: { name },
    });
    mockedSearch
      .mockResolvedValueOnce({
        label: 'S3Bucket',
        resources: [bucket('one'), bucket('two')],
        nextToken: 'after-two',
      })
      .mockResolvedValueOnce({ label: 'S3Bucket', resources: [bucket('three')] });
    render(<ResourcesPage />);

    expect(await screen.findByText('Showing 2 resources')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Load more' }));

    expect(await screen.findByText('Showing 3 resources')).toBeInTheDocument();
    expect(screen.getByText('three')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Load more' })).not.toBeInTheDocument();
    expect(mockedSearch).toHaveBeenLastCalledWith(
      'IamRole',
      undefined,
      undefined,
      50,
      {},
      'after-two'
    );
  });

  it('says when the label list fails to load and retries on request', async () => {
    mockedLabels
      .mockRejectedValueOnce(new Error('Failed to list resource labels'))
      .mockResolvedValueOnce({ labels: [{ label: 'S3Bucket', count: 1204 }] });
    render(<ResourcesPage />);

    expect(await screen.findByText(/Couldn.t load the label list/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Retry' }));
    await userEvent.click(screen.getByRole('combobox', { name: 'Label' }));
    expect(await screen.findByRole('option', { name: 'S3 bucket (1,204)' })).toBeInTheDocument();
    expect(screen.queryByText(/Couldn.t load the label list/)).not.toBeInTheDocument();
  });

  it('keeps a label from the URL pickable before the list loads', async () => {
    mockSearch = 'label=EksCluster';
    mockedLabels.mockReturnValue(new Promise(() => {}));
    render(<ResourcesPage />);

    const box = await screen.findByRole('combobox', { name: 'Label' });
    expect(box).toHaveValue('EKS cluster');
    await userEvent.click(box);
    expect(screen.getByRole('option', { name: 'EKS cluster' })).toBeInTheDocument();
  });

  it('picks a property and one of its values from lists, and filters on them', async () => {
    mockSearch = 'label=IamRole';
    mockedValues.mockResolvedValue({
      values: [
        { value: 'false', count: 300 },
        { value: 'true', count: 56 },
      ],
      more: false,
    });
    render(<ResourcesPage />);

    const search = screen.getByRole('button', { name: 'Search' });
    await userEvent.selectOptions(
      await screen.findByLabelText('Property'),
      await screen.findByRole('option', { name: 'is_admin_role' })
    );
    expect(search).toBeDisabled();
    expect(mockedValues).toHaveBeenLastCalledWith('IamRole', 'is_admin_role', expect.anything());

    await userEvent.selectOptions(
      screen.getByLabelText('Value'),
      await screen.findByRole('option', { name: 'true (56)' })
    );
    await userEvent.click(search);
    expect(push).toHaveBeenCalledWith('/resources?label=IamRole&property=is_admin_role&value=true');
  });

  it('keeps a text box for a property with too many values to list', async () => {
    mockedValues.mockResolvedValue({ values: [{ value: 'a', count: 1 }], more: true });
    render(<ResourcesPage />);

    expect(screen.getByLabelText('Value')).toBeDisabled();
    await userEvent.selectOptions(
      await screen.findByLabelText('Property'),
      await screen.findByRole('option', { name: 'name' })
    );
    const value = screen.getByLabelText('Value');
    await userEvent.type(value, 'payments-role');
    expect(value).toHaveValue('payments-role');
    expect(value.tagName).toBe('INPUT');
  });

  it('filters all labels by a property and one of its values', async () => {
    mockSearch = 'label=*';
    mockedProperties.mockResolvedValue({ properties: ['account_id', 'env'] });
    mockedValues.mockResolvedValue({
      values: [{ value: '111122223333', count: 0, name: 'prod' }],
      more: false,
    });
    render(<ResourcesPage />);

    const search = screen.getByRole('button', { name: 'Search' });

    await userEvent.selectOptions(
      screen.getByLabelText('Property'),
      await screen.findByRole('option', { name: 'account_id' })
    );
    await userEvent.selectOptions(
      screen.getByLabelText('Value'),
      await screen.findByRole('option', { name: 'prod · 111122223333' })
    );
    await userEvent.click(search);
    expect(push).toHaveBeenCalledWith('/resources?label=*&property=account_id&value=111122223333');
  });
});

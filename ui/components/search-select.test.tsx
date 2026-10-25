import { useState } from 'react';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SearchSelect, type SearchSelectOption } from './search-select';

const options: SearchSelectOption[] = [
  { value: '*', name: 'All labels' },
  { value: 'IamRole', name: 'IAM role', count: 356 },
  { value: 'S3Bucket', name: 'S3 bucket', count: 1204 },
  { value: 'Secret', name: 'Secret', count: 1140 },
];

function Harness({ onSubmit = jest.fn() }: { onSubmit?: () => void }) {
  const [value, setValue] = useState('*');
  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        onSubmit();
      }}
    >
      <SearchSelect label="Label" value={value} options={options} onChange={setValue} />
      <output data-testid="value">{value}</output>
    </form>
  );
}

const box = () => screen.getByRole('combobox', { name: 'Label' });

describe('SearchSelect', () => {
  it('narrows the list as you type and highlights the match', async () => {
    render(<Harness />);
    await userEvent.type(box(), 'sec');

    expect(screen.getAllByRole('option').map((o) => o.getAttribute('aria-label'))).toEqual([
      'Secret (1,140)',
    ]);
    expect(screen.getByText('Sec', { selector: 'mark' })).toBeInTheDocument();
  });

  it('matches the raw label as well as its display name', async () => {
    render(<Harness />);
    await userEvent.type(box(), 's3bu');

    expect(screen.getByRole('option', { name: 'S3 bucket (1,204)' })).toBeInTheDocument();
  });

  it('picks with the arrow keys and Enter without submitting the form', async () => {
    const onSubmit = jest.fn();
    render(<Harness onSubmit={onSubmit} />);
    await userEvent.click(box());
    await userEvent.keyboard('{ArrowDown}{ArrowDown}{Enter}');

    expect(screen.getByTestId('value')).toHaveTextContent('S3Bucket');
    expect(box()).toHaveValue('S3 bucket');
    expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
    expect(onSubmit).not.toHaveBeenCalled();

    // Closed, Enter submits as usual.
    await userEvent.keyboard('{Enter}');
    expect(onSubmit).toHaveBeenCalledTimes(1);
  });

  it('marks the current choice and puts the cursor on it when opened', async () => {
    render(<Harness />);
    await userEvent.click(box());

    const current = screen.getByRole('option', { name: 'All labels' });
    expect(current).toHaveAttribute('aria-selected', 'true');
    expect(box()).toHaveAttribute('aria-activedescendant', current.id);
  });

  it('starts a fresh search when tabbed into, or typed into after a pick', async () => {
    render(<Harness />);
    await userEvent.tab();
    await userEvent.keyboard('iam');
    expect(screen.getAllByRole('option').map((o) => o.getAttribute('aria-label'))).toEqual([
      'IAM role (356)',
    ]);

    await userEvent.keyboard('{Enter}');
    expect(box()).toHaveValue('IAM role');
    await userEvent.keyboard('s3');
    expect(box()).toHaveValue('s3');
    expect(screen.getByRole('option', { name: 'S3 bucket (1,204)' })).toBeInTheDocument();
  });

  it('says when nothing matches', async () => {
    render(<Harness />);
    await userEvent.type(box(), 'zzz');

    expect(screen.getByText(/No labels match/)).toHaveTextContent('No labels match “zzz”');
    expect(screen.queryAllByRole('option')).toHaveLength(0);
  });

  it('closes on Escape or blur and keeps the previous choice', async () => {
    render(<Harness />);
    await userEvent.type(box(), 'iam');
    await userEvent.keyboard('{Escape}');

    expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
    expect(box()).toHaveValue('All labels');

    await userEvent.type(box(), 'sec');
    await userEvent.tab();
    expect(box()).toHaveValue('All labels');
    expect(screen.getByTestId('value')).toHaveTextContent('*');
  });

  it('opens and closes from the arrow button', async () => {
    render(<Harness />);
    await userEvent.click(screen.getByRole('button', { name: 'Show label list' }));
    expect(screen.getByRole('listbox')).toBeInTheDocument();
    expect(box()).toHaveFocus();

    await userEvent.click(screen.getByRole('button', { name: 'Close label list' }));
    expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
  });
});

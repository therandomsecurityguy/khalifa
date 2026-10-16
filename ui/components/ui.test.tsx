import colors from 'tailwindcss/colors';
import { render, screen } from '@testing-library/react';
import {
  LINK,
  PRIMARY_BUTTON,
  RiskBadge,
  SECONDARY_BUTTON,
  SelectField,
  SeverityBadge,
  StatusBadge,
  StatusMessage,
  TextField,
  TILE_TONES,
  TONES,
} from './ui';

function hexFor(token: string): string {
  if (token === 'white') return '#ffffff';
  if (token === 'black') return '#000000';
  const [family, shade] = token.split('-');
  const value = (colors as unknown as Record<string, Record<string, string>>)[family]?.[shade];
  if (!value) throw new Error(`Unknown Tailwind colour ${token}`);
  return value;
}

function luminance(hex: string): number {
  const channels = [1, 3, 5].map((offset) => parseInt(hex.slice(offset, offset + 2), 16) / 255);
  const [r, g, b] = channels.map((channel) =>
    channel <= 0.03928 ? channel / 12.92 : Math.pow((channel + 0.055) / 1.055, 2.4)
  );
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrast(background: string, foreground: string): number {
  const [light, dark] = [luminance(background), luminance(foreground)].sort((a, b) => b - a);
  return (light + 0.05) / (dark + 0.05);
}

// Reads the unprefixed bg-/text- utilities from a class string (hover: and
// focus: variants are ignored).
function pairing(classes: string): [string, string] {
  const background = classes.match(/(?<![:\w-])bg-(white|black|[a-z]+-\d{2,3})\b/)?.[1];
  const foreground = classes.match(/(?<![:\w-])text-(white|black|[a-z]+-\d{2,3})\b/)?.[1];
  if (!background || !foreground) throw new Error(`No colour pairing in "${classes}"`);
  return [background, foreground];
}

function flatten(value: unknown): string[] {
  if (typeof value === 'string') return [value];
  return Object.values(value as Record<string, unknown>).flatMap(flatten);
}

const AA_NORMAL_TEXT = 4.5;

describe('design tokens', () => {
  it.each(flatten(TONES))('tone "%s" meets WCAG AA contrast', (classes) => {
    const [background, foreground] = pairing(classes);
    expect(contrast(hexFor(background), hexFor(foreground))).toBeGreaterThanOrEqual(AA_NORMAL_TEXT);
  });

  it.each(Object.entries(TILE_TONES))('tile "%s" value and label meet WCAG AA', (_, tile) => {
    const box = hexFor(pairing(`${tile.box} text-white`)[0]);
    expect(contrast(box, hexFor(pairing(`bg-white ${tile.value}`)[1]))).toBeGreaterThanOrEqual(
      AA_NORMAL_TEXT
    );
    expect(contrast(box, hexFor('gray-600'))).toBeGreaterThanOrEqual(AA_NORMAL_TEXT);
  });

  it.each([PRIMARY_BUTTON, SECONDARY_BUTTON, `bg-white ${LINK}`])(
    'control "%s" meets WCAG AA',
    (classes) => {
      const [background, foreground] = pairing(classes);
      expect(contrast(hexFor(background), hexFor(foreground))).toBeGreaterThanOrEqual(
        AA_NORMAL_TEXT
      );
    }
  );
});

describe('badges', () => {
  it('falls back to the unknown tone for values outside the palette', () => {
    render(
      <>
        <SeverityBadge severity="urgent" />
        <StatusBadge status="PENDING" />
        <RiskBadge level="extreme" />
      </>
    );
    expect(screen.getByText('urgent')).toHaveClass(TONES.severity.unknown.split(' ')[0]);
    expect(screen.getByText('PENDING')).toHaveClass(TONES.status.unknown.split(' ')[0]);
    expect(screen.getByText('extreme')).toHaveClass(TONES.severity.unknown.split(' ')[0]);
  });

  it('renders known severities with the requested tone', () => {
    render(<SeverityBadge severity="high" tone="soft" />);
    expect(screen.getByText('high')).toHaveClass(TONES.severitySoft.high.split(' ')[0]);
  });
});

describe('form fields', () => {
  it('associates labels with their controls', () => {
    render(
      <>
        <TextField label="Team" hint="Owning team slug" defaultValue="" />
        <SelectField label="Status" defaultValue="">
          <option value="">All</option>
        </SelectField>
      </>
    );
    const input = screen.getByLabelText('Team');
    expect(input.tagName).toBe('INPUT');
    expect(input).toHaveAccessibleDescription('Owning team slug');
    expect(screen.getByLabelText('Status').tagName).toBe('SELECT');
  });
});

describe('StatusMessage', () => {
  it('interrupts for errors and announces everything else politely', () => {
    render(
      <>
        <StatusMessage tone="error">Failed</StatusMessage>
        <StatusMessage tone="success">Saved</StatusMessage>
      </>
    );
    expect(screen.getByRole('alert')).toHaveTextContent('Failed');
    expect(screen.getByRole('status')).toHaveTextContent('Saved');
  });
});

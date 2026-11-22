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

function colorFor(token: string): string {
  if (token === 'white') return '#ffffff';
  if (token === 'black') return '#000000';
  const [family, shade] = token.split('-');
  const value = (colors as unknown as Record<string, Record<string, string>>)[family]?.[shade];
  if (!value) throw new Error(`Unknown Tailwind colour ${token}`);
  return value;
}

// Tailwind v4 exposes the palette as CSS colour strings — `oklch(…)`, `#fff`,
// occasionally `rgb(…)` — so convert them to sRGB channels before computing
// luminance. (v3 returned plain 6-digit hex, which a naive slice parsed.)
function channelsFor(color: string): number[] {
  const value = color.trim();
  const hex = /^#([0-9a-f]{3}|[0-9a-f]{6})$/i.exec(value);
  if (hex) {
    const digits = hex[1].length === 3 ? [...hex[1]].map((c) => c + c).join('') : hex[1];
    return [0, 2, 4].map((offset) => parseInt(digits.slice(offset, offset + 2), 16) / 255);
  }
  const rgb = /^rgba?\(([^)]+)\)$/i.exec(value);
  if (rgb) {
    return rgb[1]
      .split(/[\s,/]+/)
      .filter(Boolean)
      .slice(0, 3)
      .map((channel) =>
        channel.endsWith('%') ? parseFloat(channel) / 100 : parseFloat(channel) / 255
      );
  }
  const oklch = /^oklch\(\s*([0-9.]+)(%?)\s+([0-9.]+)\s+([0-9.]+)/i.exec(value);
  if (oklch) {
    const l = parseFloat(oklch[1]) / (oklch[2] === '%' ? 100 : 1);
    const chroma = parseFloat(oklch[3]);
    const hue = (parseFloat(oklch[4]) * Math.PI) / 180;
    const a = chroma * Math.cos(hue);
    const b = chroma * Math.sin(hue);
    const lCube = (l + 0.3963377774 * a + 0.2158037573 * b) ** 3;
    const mCube = (l - 0.1055613458 * a - 0.0638541728 * b) ** 3;
    const sCube = (l - 0.0894841775 * a - 1.291485548 * b) ** 3;
    // oklab -> linear sRGB -> gamma-encoded sRGB.
    return [
      4.0767416621 * lCube - 3.3077115913 * mCube + 0.2309699292 * sCube,
      -1.2684380046 * lCube + 2.6097574011 * mCube - 0.3413193965 * sCube,
      -0.0041960863 * lCube - 0.7034186147 * mCube + 1.707614701 * sCube,
    ].map((linear) => {
      const encoded = linear <= 0.0031308 ? 12.92 * linear : 1.055 * linear ** (1 / 2.4) - 0.055;
      return Math.min(1, Math.max(0, encoded));
    });
  }
  throw new Error(`Unsupported colour value ${value}`);
}

function luminance(color: string): number {
  const [r, g, b] = channelsFor(color).map((channel) =>
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
    expect(contrast(colorFor(background), colorFor(foreground))).toBeGreaterThanOrEqual(
      AA_NORMAL_TEXT
    );
  });

  it.each(Object.entries(TILE_TONES))('tile "%s" value and label meet WCAG AA', (_, tile) => {
    const box = colorFor(pairing(`${tile.box} text-white`)[0]);
    expect(contrast(box, colorFor(pairing(`bg-white ${tile.value}`)[1]))).toBeGreaterThanOrEqual(
      AA_NORMAL_TEXT
    );
    expect(contrast(box, colorFor('gray-600'))).toBeGreaterThanOrEqual(AA_NORMAL_TEXT);
  });

  it.each([PRIMARY_BUTTON, SECONDARY_BUTTON, `bg-white ${LINK}`])(
    'control "%s" meets WCAG AA',
    (classes) => {
      const [background, foreground] = pairing(classes);
      expect(contrast(colorFor(background), colorFor(foreground))).toBeGreaterThanOrEqual(
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

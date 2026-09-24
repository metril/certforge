import { render, screen } from '@testing-library/react';
import { expect, it } from 'vitest';
import { fmtDate } from '@/lib/time';
import { iso, NOW } from '@/test/fixtures';
import { ValidityBar, validityGeometry } from './ValidityBar';

it('maps times onto the lifetime', () => {
  const g = validityGeometry({ notBefore: iso(-30), notAfter: iso(60), renewAt: iso(30), now: NOW });
  expect(g.now).toBeCloseTo(33.33, 1);
  expect(g.elapsed).toBeCloseTo(33.33, 1);
  expect(g.window).toEqual({ from: expect.closeTo(66.67, 1), to: 100 });
  expect(g.ghost).toBeNull();
});

it('extends the domain for a ghost successor and clamps now after expiry', () => {
  const g = validityGeometry({ notBefore: iso(-90), notAfter: iso(-10), ghost: { notBefore: iso(-20), notAfter: iso(70) }, now: NOW });
  expect(g.end).toBeCloseTo(50, 0);
  expect(g.elapsed).toBeCloseTo(50, 0);
  expect(g.ghost!.to).toBe(100);
});

it('places the notch before the window when now precedes notBefore', () => {
  const g = validityGeometry({ notBefore: iso(10), notAfter: iso(100), now: NOW });
  expect(g.now).toBe(0);
  expect(g.elapsed).toBe(0);
});

it('clamps the notch to the end once past notAfter with no ghost', () => {
  const g = validityGeometry({ notBefore: iso(-100), notAfter: iso(-10), now: NOW });
  expect(g.now).toBe(100);
  expect(g.end).toBe(100);
  expect(g.elapsed).toBe(100);
});

it('describes itself for screen readers and shows labels when full', () => {
  render(<ValidityBar notBefore={iso(-30)} notAfter={iso(60)} renewAt={iso(30)} tone="valid" now={NOW} size="full" />);
  expect(screen.getByRole('img')).toHaveAccessibleName(`Valid ${fmtDate(iso(-30))} to ${fmtDate(iso(60))}, expires in 60 d, renews in 30 d`);
  expect(screen.getByText('renews in 30 d')).toBeInTheDocument();
  expect(screen.getByText(`Expires ${fmtDate(iso(60))} (in 60 d)`)).toBeInTheDocument();
});

it('describes an expired certificate without a renews phrase', () => {
  render(<ValidityBar notBefore={iso(-100)} notAfter={iso(-10)} renewAt={iso(-5)} tone="expired" now={NOW} />);
  expect(screen.getByRole('img')).toHaveAccessibleName(`Valid ${fmtDate(iso(-100))} to ${fmtDate(iso(-10))}, expired 10 d ago`);
});

it('renders a ghost segment for the next version', () => {
  const { container } = render(
    <ValidityBar notBefore={iso(-90)} notAfter={iso(-10)} ghost={{ notBefore: iso(-20), notAfter: iso(70) }} tone="expired" now={NOW} size="full" />,
  );
  expect(container.querySelector('.border-dashed')).toBeInTheDocument();
});

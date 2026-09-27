import { render, screen } from '@testing-library/react';
import { expect, it } from 'vitest';
import { TooltipProvider } from '@/components/ui/tooltip';
import { fmtDate } from '@/lib/time';
import { iso, NOW } from '@/test/fixtures';
import { ValidityBar, validityGeometry } from './ValidityBar';

function expectFinitePercents(g: ReturnType<typeof validityGeometry>) {
  const values = [g.end, g.now, g.elapsed, g.window?.from, g.window?.to, g.ghost?.from, g.ghost?.to].filter((v): v is number => v !== undefined);
  expect(values.length).toBeGreaterThan(0);
  for (const v of values) {
    expect(Number.isFinite(v)).toBe(true);
    expect(v).toBeGreaterThanOrEqual(0);
    expect(v).toBeLessThanOrEqual(100);
  }
}

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

// Fix round 1 (#2): the notch must actually fall inside the renewal window
// when renewAt < now < notAfter, not just be exercised at the window edges.
it('places the notch inside the renewal window when renewAt < now < notAfter', () => {
  const g = validityGeometry({ notBefore: iso(-80), notAfter: iso(20), renewAt: iso(-10), now: NOW });
  expect(g.window).not.toBeNull();
  expect(g.now).toBeGreaterThanOrEqual(g.window!.from);
  expect(g.now).toBeLessThanOrEqual(g.window!.to);
});

// Fix round 1 (#2): degenerate spans must never produce NaN/Infinity or an
// out-of-range percentage; the `Math.max(domainEnd - start, 1)` floor and the
// finite guard in `clamp` are what keep these safe.
it('keeps every percentage finite and clamped for a zero-length validity span', () => {
  expectFinitePercents(validityGeometry({ notBefore: iso(0), notAfter: iso(0), renewAt: iso(0), now: NOW }));
});

it('keeps every percentage finite and clamped for an inverted validity span', () => {
  expectFinitePercents(validityGeometry({ notBefore: iso(10), notAfter: iso(-10), renewAt: iso(0), now: NOW }));
});

// Fix round 1 (#6): a malformed timestamp must not leak NaN into a `width`/`left` style.
it('keeps every percentage finite for a malformed timestamp', () => {
  expectFinitePercents(validityGeometry({ notBefore: 'not-a-date', notAfter: iso(10), now: NOW }));
});

// Fix round 1 (#4): a ghost span that's inverted, zero-length, or identical
// to the current version's own span is not a real successor and must not be
// rendered as one.
it('skips an inverted, zero-length, or duplicate-of-current ghost span', () => {
  const current = { notBefore: iso(-90), notAfter: iso(-10) };
  expect(validityGeometry({ ...current, ghost: { notBefore: iso(70), notAfter: iso(-20) }, now: NOW }).ghost).toBeNull();
  expect(validityGeometry({ ...current, ghost: { notBefore: iso(10), notAfter: iso(10) }, now: NOW }).ghost).toBeNull();
  expect(validityGeometry({ ...current, ghost: { ...current }, now: NOW }).ghost).toBeNull();
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

// Fix round 1 (#4): the ghost test now asserts the segment's actual position
// and width (not just that some dashed element exists), and that the
// successor is named in the accessible text.
it('renders a ghost segment at the successor span and names it in the accessible text', () => {
  const { container } = render(
    <ValidityBar notBefore={iso(-90)} notAfter={iso(-10)} ghost={{ notBefore: iso(-20), notAfter: iso(70) }} tone="expired" now={NOW} size="full" />,
  );
  const ghostEl = container.querySelector<HTMLElement>('.border-dashed');
  expect(ghostEl).toBeInTheDocument();
  expect(parseFloat(ghostEl!.style.left)).toBeCloseTo(43.75, 1);
  expect(parseFloat(ghostEl!.style.width)).toBeCloseTo(56.25, 1);
  expect(screen.getByRole('img')).toHaveAccessibleName(
    `Valid ${fmtDate(iso(-90))} to ${fmtDate(iso(-10))}, expired 10 d ago, next version until ${fmtDate(iso(70))}`,
  );
});

// Fix round 1 (#4): an invalid ghost span must not render a dashed segment.
it('does not render a ghost segment for an inverted ghost span', () => {
  const { container } = render(
    <ValidityBar notBefore={iso(-90)} notAfter={iso(-10)} ghost={{ notBefore: iso(70), notAfter: iso(-20) }} tone="expired" now={NOW} size="full" />,
  );
  expect(container.querySelector('.border-dashed')).not.toBeInTheDocument();
});

// Fix round 1 (#3): once the renewal window starts past ~80% of the track, the
// renew label must switch to right-edge anchoring instead of centering on
// `from`, which would push its right half past the track's own edge.
it('anchors the renew label to the right edge once the window starts past 80%', () => {
  render(<ValidityBar notBefore={iso(-30)} notAfter={iso(60)} renewAt={iso(55)} tone="expiring" now={NOW} size="full" />);
  const label = screen.getByText(/^renews/);
  expect(label).toHaveClass('right-0');
  expect(label).not.toHaveClass('-translate-x-1/2');
  expect(label.style.left).toBe('');
});

it('keeps the renew label left-anchored with a translate when the window starts before 80%', () => {
  render(<ValidityBar notBefore={iso(-30)} notAfter={iso(60)} renewAt={iso(30)} tone="valid" now={NOW} size="full" />);
  const label = screen.getByText(/^renews/);
  expect(label).toHaveClass('-translate-x-1/2');
  expect(label).not.toHaveClass('right-0');
});

// Task 7: the ARI window geometry — inside the lifetime, clamped when it
// overruns one edge, and null when the window falls entirely outside it.
it('computes the ARI window geometry: inside, clamped, and outside', () => {
  const inside = validityGeometry({ notBefore: iso(-30), notAfter: iso(60), ari: { start: iso(0), end: iso(20), checkedAt: iso(0) }, now: NOW });
  expect(inside.ari).toEqual({ from: expect.closeTo(33.33, 1), to: expect.closeTo(55.56, 1) });

  const clamped = validityGeometry({ notBefore: iso(-30), notAfter: iso(60), ari: { start: iso(-40), end: iso(10), checkedAt: iso(0) }, now: NOW });
  expect(clamped.ari).toEqual({ from: 0, to: expect.closeTo(44.44, 1) });

  const outside = validityGeometry({ notBefore: iso(-30), notAfter: iso(60), ari: { start: iso(70), end: iso(90), checkedAt: iso(0) }, now: NOW });
  expect(outside.ari).toBeNull();

  expect(validityGeometry({ notBefore: iso(-30), notAfter: iso(60), ari: null, now: NOW }).ari).toBeNull();
});

it("appends the ARI window to the bar's accessible label", () => {
  render(
    <TooltipProvider>
      <ValidityBar
        notBefore={iso(-30)}
        notAfter={iso(60)}
        tone="valid"
        now={NOW}
        ari={{ start: iso(0), end: iso(20), checkedAt: iso(0) }}
      />
    </TooltipProvider>,
  );
  expect(screen.getByRole('img')).toHaveAccessibleName(`Valid ${fmtDate(iso(-30))} to ${fmtDate(iso(60))}, expires in 60 d, ARI window ${fmtDate(iso(0))} to ${fmtDate(iso(20))}`);
});

// Pre-flight C2: the ARI help must be reachable outside the decorative
// role="img" bar and outside the aria-hidden legend row — a screen reader
// user tabbing through the page must actually land on it.
it('keeps the ARI HelpTip reachable outside the role="img" bar and the aria-hidden legend', () => {
  render(
    <TooltipProvider>
      <ValidityBar
        notBefore={iso(-30)}
        notAfter={iso(60)}
        tone="valid"
        now={NOW}
        size="full"
        ari={{ start: iso(0), end: iso(20), checkedAt: iso(0) }}
      />
    </TooltipProvider>,
  );
  const helpButton = screen.getByRole('button', { name: 'Help' });
  for (let el: HTMLElement | null = helpButton; el; el = el.parentElement) {
    expect(el.getAttribute('role')).not.toBe('img');
    expect(el.getAttribute('aria-hidden')).not.toBe('true');
  }
});

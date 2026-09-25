import { useMemo } from 'react';
import { fireEvent, render } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { useShortcuts } from './shortcuts';

function H({ go, nc }: { go: () => void; nc: () => void }) {
  useShortcuts(useMemo(() => ({ 'g o': go, 'n c': nc }), [go, nc]));
  return <input aria-label="field" />;
}

it('runs two-key sequences and ignores typing in inputs', () => {
  const go = vi.fn();
  const nc = vi.fn();
  const { getByLabelText } = render(<H go={go} nc={nc} />);
  fireEvent.keyDown(window, { key: 'g' });
  fireEvent.keyDown(window, { key: 'o' });
  expect(go).toHaveBeenCalledTimes(1);
  fireEvent.keyDown(window, { key: 'g' });
  fireEvent.keyDown(window, { key: 'x' });
  fireEvent.keyDown(window, { key: 'n' });
  fireEvent.keyDown(window, { key: 'c' });
  expect(nc).toHaveBeenCalledTimes(1);
  fireEvent.keyDown(getByLabelText('field'), { key: 'g' });
  fireEvent.keyDown(getByLabelText('field'), { key: 'o' });
  expect(go).toHaveBeenCalledTimes(1);
});

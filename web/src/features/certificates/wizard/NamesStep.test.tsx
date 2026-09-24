import { useReducer } from 'react';
import { screen, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { renderUI } from '@/test/render';
import { NamesStep } from './NamesStep';
import { initialWizard, wizardReducer } from './state';

function H() {
  const [state, dispatch] = useReducer(wizardReducer, initialWizard);
  return <NamesStep state={state} dispatch={dispatch} />;
}

it('turns a paste into zone-grouped chips with the first name as CN', async () => {
  const { user } = renderUI(<H />);
  await user.click(screen.getByLabelText('Names'));
  await user.paste('www.example.com, *.example.com api.other.net\n10.0.0.1 bad_name.example.com');
  expect(screen.getByTestId('cn')).toHaveTextContent('www.example.com');
  const zone = screen.getByRole('region', { name: 'example.com' });
  expect(within(zone).getByText('DNS only')).toBeInTheDocument();
  expect(screen.getByRole('region', { name: 'other.net' })).toBeInTheDocument();
  expect(screen.getByRole('region', { name: 'IP addresses' })).toBeInTheDocument();
  expect(screen.getByRole('region', { name: 'Invalid' })).toBeInTheDocument();
  expect(screen.getByText('5 names')).toBeInTheDocument();
});

it('makes another name the common name', async () => {
  const { user } = renderUI(<H />);
  await user.click(screen.getByLabelText('Names'));
  await user.paste('www.example.com api.other.net');
  await user.click(screen.getByRole('button', { name: 'Make api.other.net the common name' }));
  expect(screen.getByTestId('cn')).toHaveTextContent('api.other.net');
});

it('handles a paste of 200 names and blocks with a clear limit', async () => {
  const { user } = renderUI(<H />);
  const text = Array.from({ length: 230 }, (_, i) => `host${i % 200}.zone${(i % 200) % 9}.example.com`).join('\n');
  await user.click(screen.getByLabelText('Names'));
  await user.paste(text);
  expect(screen.getAllByRole('button', { name: /^Remove / })).toHaveLength(200);
  expect(screen.getByRole('alert')).toHaveTextContent('100 names max per certificate');
  expect(screen.getByText('200 names')).toBeInTheDocument();
});

// Controller ruling (docs/design.md "Certificate create wizard" step 1): the
// chip grid must wrap, not scroll, at 375px with a 16px gutter. jsdom has no
// layout engine, so the closest automatable proxy is asserting the chip
// container keeps Tailwind's `flex-wrap` (the mechanism that makes wrapping
// happen) rather than a fixed/no-wrap layout, and that the step itself sets
// no min-width that would force a wider viewport.
it('lays out name chips in a wrapping flex row', async () => {
  const { user, container } = renderUI(<H />);
  await user.click(screen.getByLabelText('Names'));
  await user.paste('a.example.com b.example.com');
  const zone = screen.getByRole('region', { name: 'example.com' });
  const grid = within(zone).getByText('a.example.com').closest('div');
  expect(grid?.className).toContain('flex-wrap');
  expect(container.querySelector('[class*="min-w-"]')).toBeNull();
});

// Controller ruling: CN reassignment must also work via dnd-kit's keyboard
// sensor (the accessible alternative to pointer drag), not only the menu
// button covered above. jsdom computes every element's bounding rect as a
// zero-size box at the origin, so collision detection never finds an
// overlap; both the draggable chip and the Common name drop target are
// stubbed to the same non-zero rect here so a real KeyboardSensor
// activate-then-end sequence (Space to pick up, Space to drop) has a real
// droppable to land on, exercising the actual DndContext/onDragEnd wiring
// rather than calling the dispatch by hand.
let rectSpy: ReturnType<typeof vi.spyOn>;
beforeEach(() => {
  rectSpy = vi.spyOn(Element.prototype, 'getBoundingClientRect').mockReturnValue({
    x: 0,
    y: 0,
    top: 0,
    left: 0,
    right: 100,
    bottom: 40,
    width: 100,
    height: 40,
    toJSON() {
      return this;
    },
  } as DOMRect);
});
afterEach(() => rectSpy.mockRestore());

it('makes another name the common name by dragging with the keyboard', async () => {
  const { user } = renderUI(<H />);
  await user.click(screen.getByLabelText('Names'));
  await user.paste('www.example.com api.other.net');
  const handle = screen.getByText('api.other.net');
  handle.focus();
  await user.keyboard('[Space]');
  await new Promise((resolve) => setTimeout(resolve, 0));
  await user.keyboard('[Space]');
  expect(screen.getByTestId('cn')).toHaveTextContent('api.other.net');
});

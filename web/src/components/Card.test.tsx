import { render, screen } from '@testing-library/react';
import { expect, it } from 'vitest';
import { Card, CardBody, CardHeader, useInCard } from './Card';

function Probe() {
  return <span data-testid="probe">{String(useInCard())}</span>;
}

it('Card is a bordered panel with no shadow and provides the in-card context', () => {
  render(
    <Card data-testid="card">
      <Probe />
    </Card>,
  );
  const cls = screen.getByTestId('card').className;
  for (const c of ['rounded-md', 'border', 'border-border', 'bg-panel']) expect(cls).toContain(c);
  expect(cls).not.toContain('shadow');
  expect(screen.getByTestId('probe')).toHaveTextContent('true');
});

it('useInCard is false outside a Card', () => {
  render(<Probe />);
  expect(screen.getByTestId('probe')).toHaveTextContent('false');
});

it('CardHeader renders the title and actions over a divider; CardBody pads', () => {
  render(
    <Card>
      <CardHeader title="Names" actions={<button>Edit</button>} />
      <CardBody data-testid="body">x</CardBody>
    </Card>,
  );
  expect(screen.getByRole('heading', { name: 'Names' })).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Edit' })).toBeInTheDocument();
  expect(screen.getByRole('heading', { name: 'Names' }).parentElement!.className).toContain('border-b');
  expect(screen.getByTestId('body').className).toContain('p-4');
});

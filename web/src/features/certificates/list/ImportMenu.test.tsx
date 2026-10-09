import userEvent from '@testing-library/user-event';
import { render, screen } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { TooltipProvider } from '@/components/ui/tooltip';
import { ImportMenu } from './ImportMenu';

vi.mock('@tanstack/react-router', () => ({ Link: ({ children }: { children: React.ReactNode }) => <a>{children}</a> }));

it('shows a tooltip on the Import trigger', async () => {
  const user = userEvent.setup();
  render(
    <TooltipProvider>
      <ImportMenu orgSlug="acme" canWrite />
    </TooltipProvider>,
  );
  await user.hover(screen.getByRole('button', { name: 'Import' }));
  expect(await screen.findByRole('tooltip')).toHaveTextContent('Import');
});

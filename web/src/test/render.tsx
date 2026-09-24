import type { ReactElement } from 'react';
import { render } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Providers } from '@/app/Providers';
import { makeQueryClient } from '@/lib/queryClient';

export function renderUI(ui: ReactElement) {
  const queryClient = makeQueryClient({ test: true });
  const user = userEvent.setup();
  return { user, queryClient, ...render(<Providers queryClient={queryClient}>{ui}</Providers>) };
}

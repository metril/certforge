import type { ReactElement } from 'react';
import { render } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { createMemoryHistory, RouterProvider } from '@tanstack/react-router';
import { Providers } from '@/app/Providers';
import { makeQueryClient } from '@/lib/queryClient';
import { createAppRouter } from '@/router';

export function renderUI(ui: ReactElement) {
  const queryClient = makeQueryClient({ test: true });
  const user = userEvent.setup();
  return { user, queryClient, ...render(<Providers queryClient={queryClient}>{ui}</Providers>) };
}

export function renderRoute(path: string) {
  const queryClient = makeQueryClient({ test: true });
  const router = createAppRouter(queryClient, createMemoryHistory({ initialEntries: [path] }));
  const user = userEvent.setup();
  const utils = render(
    <Providers queryClient={queryClient}>
      <RouterProvider router={router} />
    </Providers>,
  );
  return { router, queryClient, user, ...utils };
}

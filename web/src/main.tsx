import '@/styles/fonts';
import '@/styles/app.css';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { RouterProvider } from '@tanstack/react-router';
import { Providers } from '@/app/Providers';
import { makeQueryClient } from '@/lib/queryClient';
import { createAppRouter } from './router';

const queryClient = makeQueryClient();
const router = createAppRouter(queryClient);

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <Providers queryClient={queryClient}>
      <RouterProvider router={router} />
    </Providers>
  </StrictMode>,
);

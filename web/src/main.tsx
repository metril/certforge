import '@/styles/fonts';
import '@/styles/app.css';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { ThemeProvider } from '@/lib/theme';
import { TooltipProvider } from '@/components/ui/tooltip';
import { ThemeToggle } from '@/components/ThemeToggle';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ThemeProvider>
      <TooltipProvider delayDuration={300}>
        <main className="p-6">
          <ThemeToggle />
        </main>
      </TooltipProvider>
    </ThemeProvider>
  </StrictMode>,
);

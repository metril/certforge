import { useState, type ReactNode } from 'react';
import { useNavigate } from '@tanstack/react-router';
import { Menu } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Sheet, SheetContent, SheetTitle, SheetTrigger } from '@/components/ui/sheet';
import { useActiveOrgSlug } from '@/lib/org';
import { useShortcuts } from '@/lib/shortcuts';
import { useMediaQuery } from '@/lib/useMediaQuery';
import { cn } from '@/lib/utils';
import { Sidebar } from './Sidebar';
import { Wordmark } from './Wordmark';

export function AppShell({ children }: { children: ReactNode }) {
  const wide = useMediaQuery('(min-width: 1280px)');
  const [drawer, setDrawer] = useState(false);
  const navigate = useNavigate();
  const org = useActiveOrgSlug();

  // Reserves the `g o` / `g c` shortcut registry (spec: Cross-cutting
  // patterns) and the Ctrl/Cmd-K binding for Task 17's command palette;
  // `g l` (Clients) is left unregistered until that page ships.
  useShortcuts(
    org
      ? {
          'g o': () => void navigate({ to: '/o/$org/overview', params: { org } }),
          'g c': () => void navigate({ to: '/o/$org/certificates', params: { org } }),
        }
      : {},
  );

  return (
    <div className="flex min-h-dvh bg-surface">
      <a
        href="#content"
        className="sr-only focus:not-sr-only focus:absolute focus:left-2 focus:top-2 focus:z-50 focus:bg-panel focus:px-3 focus:py-2"
      >
        Skip to content
      </a>
      <aside className={cn('sticky top-0 hidden h-dvh shrink-0 md:block', wide ? 'w-58' : 'w-14')}>
        <Sidebar compact={!wide} />
      </aside>
      <div className="flex min-w-0 flex-1 flex-col border-border bg-panel md:border-l">
        <header className="flex h-12 items-center gap-2 border-b border-border px-4 md:hidden">
          <Sheet open={drawer} onOpenChange={setDrawer}>
            <SheetTrigger asChild>
              <Button variant="ghost" size="icon" aria-label="Open navigation">
                <Menu className="size-5" aria-hidden />
              </Button>
            </SheetTrigger>
            <SheetContent side="left" className="w-64 bg-surface p-0">
              <SheetTitle className="sr-only">Navigation</SheetTitle>
              <Sidebar compact={false} onNavigate={() => setDrawer(false)} />
            </SheetContent>
          </Sheet>
          <Wordmark />
        </header>
        <main id="content" className="flex-1 px-4 py-6 md:px-8">
          {children}
        </main>
      </div>
    </div>
  );
}

import { useCallback, useEffect, useState, type ReactNode } from 'react';
import { useLocation, useNavigate } from '@tanstack/react-router';
import { Menu, Search } from 'lucide-react';
import { Sheet, SheetContent, SheetTitle, SheetTrigger } from '@/components/ui/sheet';
import { ALL_ORGS_SLUG, useActiveOrgSlug } from '@/lib/org';
import { useShortcuts } from '@/lib/shortcuts';
import { useMediaQuery } from '@/lib/useMediaQuery';
import { cn } from '@/lib/utils';
import { CommandPalette } from './CommandPalette';
import { ReadOnlyBanner } from './ReadOnlyBanner';
import { Sidebar } from './Sidebar';
import { Wordmark } from './Wordmark';
import { IconButton } from '@/components/IconButton';

export function AppShell({ children }: { children: ReactNode }) {
  const wide = useMediaQuery('(min-width: 1280px)');
  const isMdUp = useMediaQuery('(min-width: 768px)');
  const [drawer, setDrawer] = useState(false);
  const [palette, setPalette] = useState(false);
  const navigate = useNavigate();
  const org = useActiveOrgSlug();
  const pathname = useLocation({ select: (l) => l.pathname });
  const openPalette = useCallback(() => setPalette((o) => !o), []);

  // Fix round 1 (review): the drawer previously only closed through
  // `Sidebar`'s `onNavigate` callback, wired to `TargetLink`'s own
  // onClick — so an OrgSwitcher link, a `g o`/`g c` shortcut, or
  // browser back/forward left it open. Closing it on every pathname
  // change (regardless of what triggered the navigation) and whenever
  // the viewport widens past the drawer breakpoint covers all of those.
  useEffect(() => setDrawer(false), [pathname]);
  useEffect(() => {
    if (isMdUp) setDrawer(false);
  }, [isMdUp]);

  // `g o` / `g c` (spec: Cross-cutting patterns), Task 17's `n c` (new
  // certificate), and the Ctrl/Cmd-K binding, which toggles the palette so
  // a second Ctrl/Cmd-K closes it again. `g l` (Clients) is left
  // unregistered until that page ships.
  useShortcuts(
    org
      ? {
          'g o': () => void navigate({ to: '/o/$org/overview', params: { org } }),
          'g c': () => void navigate({ to: '/o/$org/certificates', params: { org } }),
          'n c': () => void navigate({ to: '/o/$org/certificates/new', params: { org } }),
        }
      : {},
    openPalette,
  );

  return (
    <div className="flex min-h-dvh bg-surface">
      <a
        href="#content"
        className="sr-only focus:not-sr-only focus:absolute focus:left-2 focus:top-2 focus:z-50 focus:bg-panel focus:px-3 focus:py-2"
      >
        Skip to content
      </a>
      <aside className={cn('sticky top-0 hidden h-dvh shrink-0 border-r border-border bg-sidebar md:block', wide ? 'w-58' : 'w-14')}>
        <Sidebar compact={!wide} onSearch={openPalette} />
      </aside>
      <div className="flex min-w-0 flex-1 flex-col bg-surface">
        <header className="flex h-12 items-center gap-2 border-b border-border px-4 md:hidden">
          <Sheet open={drawer} onOpenChange={setDrawer}>
            <SheetTrigger asChild>
              <IconButton variant="ghost" size="icon" label="Open navigation">
                <Menu className="size-5" aria-hidden />
              </IconButton>
            </SheetTrigger>
            <SheetContent side="left" className="w-64 border-r border-border bg-sidebar p-0">
              <SheetTitle className="sr-only">Navigation</SheetTitle>
              <Sidebar compact={false} onNavigate={() => setDrawer(false)} onSearch={openPalette} />
            </SheetContent>
          </Sheet>
          <Wordmark />
          <IconButton variant="ghost" size="icon" className="ml-auto" label="Search" onClick={openPalette}>
            <Search className="size-5" aria-hidden />
          </IconButton>
        </header>
        <main id="content" className="flex-1 px-4 py-6 md:px-8">
          {org === ALL_ORGS_SLUG && <ReadOnlyBanner />}
          {children}
        </main>
      </div>
      <CommandPalette open={palette} onOpenChange={setPalette} />
    </div>
  );
}

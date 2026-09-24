import { useNavigate } from '@tanstack/react-router';
import { LogOut } from 'lucide-react';
import { useLogout } from '@/api/queries/auth';
import { Button } from '@/components/ui/button';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { useMe } from '@/lib/org';
import { cn } from '@/lib/utils';
import { ThemeToggle } from './ThemeToggle';

export function UserMenu({ compact }: { compact: boolean }) {
  const me = useMe();
  const logout = useLogout();
  const navigate = useNavigate();
  const initial = me.user.displayName.slice(0, 1).toUpperCase();
  return (
    <Popover>
      <PopoverTrigger asChild>
        <button
          type="button"
          aria-label={`Account menu for ${me.user.displayName}`}
          className={cn('mx-2 flex h-10 items-center gap-2 rounded-md px-2 text-left text-sm hover:bg-subtle', compact && 'justify-center')}
        >
          <span className="inline-flex size-7 shrink-0 items-center justify-center rounded-full bg-primary text-xs font-semibold text-on-primary">
            {initial}
          </span>
          {!compact && <span className="truncate">{me.user.displayName}</span>}
        </button>
      </PopoverTrigger>
      <PopoverContent side="top" align="start" className="grid w-72 gap-4">
        <p className="truncate text-sm font-semibold">{me.user.displayName}</p>
        <div className="grid gap-1.5">
          <span className="text-xs text-ink-muted">Theme</span>
          <ThemeToggle />
        </div>
        <Button variant="outline" onClick={() => logout.mutate(undefined, { onSettled: () => void navigate({ to: '/login' }) })}>
          <LogOut className="size-4" aria-hidden />
          Sign out
        </Button>
      </PopoverContent>
    </Popover>
  );
}

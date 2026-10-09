import { useState } from 'react';
import { Bookmark, X } from 'lucide-react';
import { IconButton } from '@/components/IconButton';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';

type View = { name: string; search: Record<string, string> };
const key = (list: string) => `cf-views-${list}`;

function read(list: string): View[] {
  try {
    const v: unknown = JSON.parse(localStorage.getItem(key(list)) ?? '[]');
    return Array.isArray(v) ? (v as View[]) : [];
  } catch {
    return [];
  }
}
function write(list: string, views: View[]) {
  try {
    localStorage.setItem(key(list), JSON.stringify(views));
  } catch {
    // Storage blocked: views last for this page only.
  }
}

type Props = { list: string; current: Record<string, string | undefined>; onApply: (search: Record<string, string>) => void };

export function SavedViews({ list, current, onApply }: Props) {
  const [views, setViews] = useState<View[]>(() => read(list));
  const [name, setName] = useState('');
  const [open, setOpen] = useState(false);
  const clean = Object.fromEntries(Object.entries(current).filter((e): e is [string, string] => !!e[1]));
  const update = (next: View[]) => {
    setViews(next);
    write(list, next);
  };
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {views.map((v) => (
        <span key={v.name} className="inline-flex h-7 items-center rounded-sm border border-border text-sm">
          <button type="button" className="px-2.5 hover:bg-subtle" onClick={() => onApply(v.search)}>{v.name}</button>
          <IconButton type="button" variant="ghost" size="icon-xs" label={`Delete view ${v.name}`} className="h-full w-auto rounded-none px-1 hover:bg-subtle" onClick={() => update(views.filter((x) => x.name !== v.name))}>
            <X className="size-3.5" aria-hidden />
          </IconButton>
        </span>
      ))}
      <Popover open={open} onOpenChange={setOpen}>
        <PopoverTrigger asChild>
          <Button variant="ghost" size="sm" disabled={Object.keys(clean).length === 0}>
            <Bookmark className="size-4" aria-hidden />
            Save view
          </Button>
        </PopoverTrigger>
        <PopoverContent className="w-64">
          <form
            className="flex gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              if (!name.trim()) return;
              update([...views.filter((v) => v.name !== name.trim()), { name: name.trim(), search: clean }]);
              setName('');
              setOpen(false);
            }}
          >
            <Input aria-label="View name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Failing" />
            <Button type="submit" size="sm">Save</Button>
          </form>
        </PopoverContent>
      </Popover>
    </div>
  );
}

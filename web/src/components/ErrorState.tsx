import { CircleAlert } from 'lucide-react';
import { Button } from '@/components/ui/button';

/** A list fetch error must not look like an empty list (controller ruling,
 * fix round 1 #5): one sentence, an icon, and a Retry button. */
export function ErrorState({ message, onRetry }: { message: string; onRetry: () => void }) {
  return (
    <div className="flex flex-col items-start gap-3 border border-dashed border-failed/60 px-6 py-10">
      <p className="flex items-center gap-1.5 text-base">
        <CircleAlert className="size-4 text-failed" aria-hidden />
        {message}
      </p>
      <Button variant="outline" onClick={onRetry}>
        Retry
      </Button>
    </div>
  );
}

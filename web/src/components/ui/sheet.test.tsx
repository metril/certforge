import { useState } from 'react';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from './sheet';

function Harness({ form, dirty }: { form?: boolean; dirty?: boolean }) {
  const [open, setOpen] = useState(true);
  return (
    <div>
      <button>outside</button>
      <Sheet open={open} form={form} dirty={dirty} onOpenChange={setOpen}>
        <SheetContent>
          <SheetHeader>
            <SheetTitle>Panel</SheetTitle>
            <SheetDescription>desc</SheetDescription>
          </SheetHeader>
        </SheetContent>
      </Sheet>
    </div>
  );
}

describe('Sheet guard', () => {
  it('form sheet ignores outside clicks', async () => {
    const user = userEvent.setup({ pointerEventsCheck: 0 });
    render(<Harness form />);
    await user.click(document.body);
    expect(screen.getByText('Panel')).toBeInTheDocument();
  });

  it('read-only sheet still closes on outside click', async () => {
    const user = userEvent.setup({ pointerEventsCheck: 0 });
    render(<Harness />);
    await user.click(document.body);
    expect(screen.queryByText('Panel')).not.toBeInTheDocument();
  });

  it('clean form closes on Escape', async () => {
    const user = userEvent.setup();
    render(<Harness form dirty={false} />);
    await user.keyboard('{Escape}');
    expect(screen.queryByText('Panel')).not.toBeInTheDocument();
  });

  it('dirty form prompts; Cancel keeps it open', async () => {
    const user = userEvent.setup();
    render(<Harness form dirty />);
    await user.keyboard('{Escape}');
    expect(screen.getByText('Discard changes?')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByText('Discard changes?')).not.toBeInTheDocument();
    expect(screen.getByText('Panel')).toBeInTheDocument();
  });

  it('dirty form closes on Discard', async () => {
    const user = userEvent.setup();
    render(<Harness form dirty />);
    await user.click(screen.getByRole('button', { name: 'Close' }));
    await user.click(screen.getByRole('button', { name: 'Discard' }));
    expect(screen.queryByText('Panel')).not.toBeInTheDocument();
  });
});

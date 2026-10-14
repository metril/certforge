import * as React from 'react'
import { useBlocker } from '@tanstack/react-router'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'

export type NavLoc = { routeId: string; params: unknown; search: Record<string, unknown> }

/** Ref a form page sets to true right before its own post-save navigation. */
export function useNavBypass() {
  return React.useRef(false)
}

export function DiscardDialog({
  open,
  onCancel,
  onDiscard,
}: {
  open: boolean
  onCancel: () => void
  onDiscard: () => void
}) {
  return (
    <Dialog open={open} onOpenChange={(o) => !o && onCancel()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Discard changes?</DialogTitle>
          <DialogDescription>Your unsaved changes will be lost.</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" onClick={onCancel}>
            Cancel
          </Button>
          <Button variant="destructive" onClick={onDiscard}>
            Discard
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** Blocks router navigation (Back/Forward, links, navigate()) and tab
 * reload/close while a dirty form sheet is open, and owns the single
 * "Discard changes?" dialog shared with the Escape/X/Cancel guard.
 * `keepsOpen` exempts navigation that leaves the guarded surface in place. A
 * save/delete close (`useSheetGuard().close`, a form page's `bypass`) and the guard's
 * confirmed discard lift the block through `bypass`. */
export function NavGuard({
  keepsOpen,
  active,
  confirming,
  setConfirming,
  bypass,
  onDiscard,
}: {
  keepsOpen: (cur: NavLoc, next: NavLoc) => boolean
  active: boolean
  confirming: boolean
  setConfirming: (c: boolean) => void
  bypass: React.MutableRefObject<boolean>
  onDiscard: () => void
}) {
  const resolver = useBlocker({
    shouldBlockFn: ({ current, next }) =>
      !bypass.current && !keepsOpen(current as NavLoc, next as NavLoc),
    withResolver: true,
    disabled: !active,
    enableBeforeUnload: active,
  })
  const blocked = resolver.status === 'blocked'
  const cancel = () => {
    if (blocked) resolver.reset()
    setConfirming(false)
  }
  return (
    <DiscardDialog
      open={active && (blocked || confirming)}
      onCancel={cancel}
      onDiscard={() => {
        bypass.current = true
        setConfirming(false)
        if (blocked) resolver.proceed()
        else onDiscard()
      }}
    />
  )
}

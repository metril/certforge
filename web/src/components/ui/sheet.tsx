"use client"

import * as React from "react"
import { cn } from "@/lib/utils"
import { XIcon } from "lucide-react"
import { Dialog as SheetPrimitive } from "radix-ui"
import { useRouter } from "@tanstack/react-router"
import { DiscardDialog, NavGuard, type NavLoc as Loc } from "@/components/NavGuard"
import { IconButton } from "@/components/IconButton"

const SheetFormContext = React.createContext(false)

type SheetProps = React.ComponentProps<typeof SheetPrimitive.Root> & {
  /** Form sheet: outside clicks never close it. */
  form?: boolean
  /** With `form`: closing asks "Discard changes?" first. */
  dirty?: boolean
  /** From `useSheetGuard`: lets a save/delete close skip the navigation block. */
  guard?: SheetGuard
}

type SheetGuard = { ref: React.MutableRefObject<boolean>; close: () => void }

/** Call `guard.close()` instead of `onOpenChange(false)` once a save or delete
 * has succeeded: the close navigates (drops the URL param) while `dirty` may
 * still be true, which the navigation block must let through. */
function useSheetGuard(onOpenChange: (open: boolean) => void): SheetGuard {
  const ref = React.useRef(false)
  const latest = React.useRef(onOpenChange)
  latest.current = onOpenChange
  return React.useMemo(
    () => ({
      ref,
      close: () => {
        ref.current = true
        latest.current(false)
      },
    }),
    []
  )
}

// Search keys that open a side panel from the URL. Navigation that keeps them
// unchanged (same route) leaves the sheet open, so it is never blocked.
const SHEET_KEYS = ['edit', 'view'] as const

function keepsSheetOpen(cur: Loc, next: Loc) {
  return (
    cur.routeId === next.routeId &&
    JSON.stringify(cur.params) === JSON.stringify(next.params) &&
    SHEET_KEYS.every((k) => cur.search[k] === next.search[k])
  )
}

function Sheet({ form = false, dirty = false, guard, onOpenChange, ...props }: SheetProps) {
  const [confirming, setConfirming] = React.useState(false)
  const ownBypass = React.useRef(false)
  const bypass = guard?.ref ?? ownBypass
  const router = useRouter({ warn: false })
  const guarded = form && dirty
  const open = props.open !== false
  React.useEffect(() => {
    if (!open || !guarded) bypass.current = false
  }, [open, guarded, bypass])
  const discard = () => onOpenChange?.(false)
  return (
    <SheetFormContext.Provider value={form}>
      <SheetPrimitive.Root
        data-slot="sheet"
        {...props}
        onOpenChange={(o) => {
          if (!o && guarded) setConfirming(true)
          else onOpenChange?.(o)
        }}
      />
      {router && form ? (
        <NavGuard
          keepsOpen={keepsSheetOpen}
          active={guarded && open}
          confirming={confirming}
          setConfirming={setConfirming}
          bypass={bypass}
          onDiscard={discard}
        />
      ) : (
        guarded && (
          <DiscardDialog
            open={confirming}
            onCancel={() => setConfirming(false)}
            onDiscard={() => {
              setConfirming(false)
              discard()
            }}
          />
        )
      )}
    </SheetFormContext.Provider>
  )
}

const SheetTrigger = React.forwardRef<
  React.ComponentRef<typeof SheetPrimitive.Trigger>,
  React.ComponentProps<typeof SheetPrimitive.Trigger>
>(function SheetTrigger({ ...props }, ref) {
  return <SheetPrimitive.Trigger ref={ref} data-slot="sheet-trigger" {...props} />
})
SheetTrigger.displayName = "SheetTrigger"

const SheetClose = React.forwardRef<
  React.ComponentRef<typeof SheetPrimitive.Close>,
  React.ComponentProps<typeof SheetPrimitive.Close>
>(function SheetClose({ ...props }, ref) {
  return <SheetPrimitive.Close ref={ref} data-slot="sheet-close" {...props} />
})
SheetClose.displayName = "SheetClose"

function SheetPortal({
  ...props
}: React.ComponentProps<typeof SheetPrimitive.Portal>) {
  return <SheetPrimitive.Portal data-slot="sheet-portal" {...props} />
}

// C1 (Critical): SheetOverlay had no forwardRef, matching the DialogOverlay
// issue — Radix's internal scroll-lock composition attaches a ref to it even
// though app code never passes it through `asChild`.
const SheetOverlay = React.forwardRef<
  React.ComponentRef<typeof SheetPrimitive.Overlay>,
  React.ComponentProps<typeof SheetPrimitive.Overlay>
>(function SheetOverlay({ className, ...props }, ref) {
  return (
    <SheetPrimitive.Overlay
      ref={ref}
      data-slot="sheet-overlay"
      className={cn(
        "fixed inset-0 z-50 bg-black/50 data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:animate-in data-[state=open]:fade-in-0",
        className
      )}
      {...props}
    />
  )
})
SheetOverlay.displayName = "SheetOverlay"

const SIZE_CLASS = { sm: 'sm:max-w-md', md: 'sm:max-w-lg', lg: 'sm:max-w-2xl', xl: 'sm:max-w-3xl' } as const

const SheetContent = React.forwardRef<
  React.ComponentRef<typeof SheetPrimitive.Content>,
  React.ComponentProps<typeof SheetPrimitive.Content> & { side?: 'top' | 'right' | 'bottom' | 'left'; showCloseButton?: boolean; size?: 'sm' | 'md' | 'lg' | 'xl' }
>(function SheetContent({ className, children, side = 'right', size = 'md', showCloseButton = true, onInteractOutside, ...props }, ref) {
  const form = React.useContext(SheetFormContext)
  return (
    <SheetPortal>
      <SheetOverlay />
      <SheetPrimitive.Content
        ref={ref}
        data-slot="sheet-content"
        className={cn(
          'fixed z-50 flex flex-col bg-raised shadow-lg transition ease-in-out data-[state=closed]:animate-out data-[state=closed]:duration-300 data-[state=open]:animate-in data-[state=open]:duration-500',
          side === 'right' && 'inset-y-0 right-0 h-full w-full overflow-hidden border-l data-[state=closed]:slide-out-to-right data-[state=open]:slide-in-from-right',
          side === 'left' && 'inset-y-0 left-0 h-full w-full overflow-hidden border-r data-[state=closed]:slide-out-to-left data-[state=open]:slide-in-from-left',
          (side === 'left' || side === 'right') && SIZE_CLASS[size],
          (side === 'top' || side === 'bottom') && 'gap-4',
          side === 'top' && 'inset-x-0 top-0 h-auto border-b data-[state=closed]:slide-out-to-top data-[state=open]:slide-in-from-top',
          side === 'bottom' && 'inset-x-0 bottom-0 h-auto border-t data-[state=closed]:slide-out-to-bottom data-[state=open]:slide-in-from-bottom',
          className,
        )}
        onInteractOutside={(e) => {
          if (form) e.preventDefault()
          onInteractOutside?.(e)
        }}
        {...props}
      >
        {children}
        {showCloseButton && (
          <SheetPrimitive.Close asChild>
            <IconButton
              label="Close"
              // Radix focuses the close button when the content has nothing else
              // focusable; keep that from popping the tooltip (hover still shows it).
              onFocus={(e) => e.preventDefault()}
              variant="ghost"
              size="icon-xs"
              className="absolute top-4 right-4 size-auto rounded-xs p-0 opacity-70 ring-offset-background transition-opacity hover:bg-transparent hover:opacity-100 focus:ring-2 focus:ring-ring focus:ring-offset-2 focus:outline-hidden disabled:pointer-events-none data-[state=open]:bg-secondary"
            >
              <XIcon className="size-4" />
            </IconButton>
          </SheetPrimitive.Close>
        )}
      </SheetPrimitive.Content>
    </SheetPortal>
  )
})
SheetContent.displayName = "SheetContent"

const SheetHeader = React.forwardRef<React.ComponentRef<'div'>, React.ComponentProps<'div'>>(function SheetHeader({ className, ...props }, ref) {
  return <div ref={ref} data-slot="sheet-header" className={cn('flex shrink-0 flex-col gap-1.5 border-b border-border p-4', className)} {...props} />
})
SheetHeader.displayName = 'SheetHeader'

const SheetBody = React.forwardRef<React.ComponentRef<'div'>, React.ComponentProps<'div'>>(function SheetBody({ className, ...props }, ref) {
  return <div ref={ref} data-slot="sheet-body" className={cn('grid min-h-0 flex-1 content-start gap-4 overflow-y-auto px-4 py-4', className)} {...props} />
})
SheetBody.displayName = 'SheetBody'

const SheetFooter = React.forwardRef<React.ComponentRef<'div'>, React.ComponentProps<'div'>>(function SheetFooter({ className, ...props }, ref) {
  return <div ref={ref} data-slot="sheet-footer" className={cn('flex shrink-0 flex-row justify-end gap-2 border-t border-border bg-raised p-4', className)} {...props} />
})
SheetFooter.displayName = 'SheetFooter'

const SheetTitle = React.forwardRef<
  React.ComponentRef<typeof SheetPrimitive.Title>,
  React.ComponentProps<typeof SheetPrimitive.Title>
>(function SheetTitle({ className, ...props }, ref) {
  return (
    <SheetPrimitive.Title
      ref={ref}
      data-slot="sheet-title"
      className={cn("font-semibold text-foreground", className)}
      {...props}
    />
  )
})
SheetTitle.displayName = "SheetTitle"

const SheetDescription = React.forwardRef<
  React.ComponentRef<typeof SheetPrimitive.Description>,
  React.ComponentProps<typeof SheetPrimitive.Description>
>(function SheetDescription({ className, ...props }, ref) {
  return (
    <SheetPrimitive.Description
      ref={ref}
      data-slot="sheet-description"
      className={cn("text-sm text-muted-foreground", className)}
      {...props}
    />
  )
})
SheetDescription.displayName = "SheetDescription"

export { DiscardDialog }
export { Sheet, useSheetGuard, SheetTrigger, SheetClose, SheetContent, SheetHeader, SheetBody, SheetFooter, SheetTitle, SheetDescription }

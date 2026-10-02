"use client"

import * as React from "react"
import { cn } from "@/lib/utils"
import { XIcon } from "lucide-react"
import { Dialog as SheetPrimitive } from "radix-ui"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"

const SheetFormContext = React.createContext(false)

type SheetProps = React.ComponentProps<typeof SheetPrimitive.Root> & {
  /** Form sheet: outside clicks never close it. */
  form?: boolean
  /** With `form`: closing asks "Discard changes?" first. */
  dirty?: boolean
}

function Sheet({ form = false, dirty = false, onOpenChange, ...props }: SheetProps) {
  const [confirming, setConfirming] = React.useState(false)
  const guarded = form && dirty
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
      {guarded && (
        <Dialog open={confirming} onOpenChange={setConfirming}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Discard changes?</DialogTitle>
              <DialogDescription>Your unsaved changes will be lost.</DialogDescription>
            </DialogHeader>
            <DialogFooter>
              <Button variant="outline" onClick={() => setConfirming(false)}>
                Cancel
              </Button>
              <Button
                variant="destructive"
                onClick={() => {
                  setConfirming(false)
                  onOpenChange?.(false)
                }}
              >
                Discard
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
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

const SheetContent = React.forwardRef<
  React.ComponentRef<typeof SheetPrimitive.Content>,
  React.ComponentProps<typeof SheetPrimitive.Content> & {
    side?: "top" | "right" | "bottom" | "left"
    showCloseButton?: boolean
  }
>(function SheetContent(
  { className, children, side = "right", showCloseButton = true, onInteractOutside, ...props },
  ref
) {
  const form = React.useContext(SheetFormContext)
  return (
    <SheetPortal>
      <SheetOverlay />
      <SheetPrimitive.Content
        ref={ref}
        data-slot="sheet-content"
        className={cn(
          "fixed z-50 flex flex-col gap-4 bg-panel shadow-lg transition ease-in-out data-[state=closed]:animate-out data-[state=closed]:duration-300 data-[state=open]:animate-in data-[state=open]:duration-500",
          side === "right" &&
            "inset-y-0 right-0 h-full w-3/4 border-l data-[state=closed]:slide-out-to-right data-[state=open]:slide-in-from-right sm:max-w-sm",
          side === "left" &&
            "inset-y-0 left-0 h-full w-3/4 border-r data-[state=closed]:slide-out-to-left data-[state=open]:slide-in-from-left sm:max-w-sm",
          side === "top" &&
            "inset-x-0 top-0 h-auto border-b data-[state=closed]:slide-out-to-top data-[state=open]:slide-in-from-top",
          side === "bottom" &&
            "inset-x-0 bottom-0 h-auto border-t data-[state=closed]:slide-out-to-bottom data-[state=open]:slide-in-from-bottom",
          className
        )}
        onInteractOutside={(e) => {
          if (form) e.preventDefault()
          onInteractOutside?.(e)
        }}
        {...props}
      >
        {children}
        {showCloseButton && (
          <SheetPrimitive.Close className="absolute top-4 right-4 rounded-xs opacity-70 ring-offset-background transition-opacity hover:opacity-100 focus:ring-2 focus:ring-ring focus:ring-offset-2 focus:outline-hidden disabled:pointer-events-none data-[state=open]:bg-secondary">
            <XIcon className="size-4" />
            <span className="sr-only">Close</span>
          </SheetPrimitive.Close>
        )}
      </SheetPrimitive.Content>
    </SheetPortal>
  )
})
SheetContent.displayName = "SheetContent"

const SheetHeader = React.forwardRef<
  React.ComponentRef<"div">,
  React.ComponentProps<"div">
>(function SheetHeader({ className, ...props }, ref) {
  return (
    <div
      ref={ref}
      data-slot="sheet-header"
      className={cn("flex flex-col gap-1.5 p-4", className)}
      {...props}
    />
  )
})
SheetHeader.displayName = "SheetHeader"

const SheetFooter = React.forwardRef<
  React.ComponentRef<"div">,
  React.ComponentProps<"div">
>(function SheetFooter({ className, ...props }, ref) {
  return (
    <div
      ref={ref}
      data-slot="sheet-footer"
      className={cn("mt-auto flex flex-col gap-2 p-4", className)}
      {...props}
    />
  )
})
SheetFooter.displayName = "SheetFooter"

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

export {
  Sheet,
  SheetTrigger,
  SheetClose,
  SheetContent,
  SheetHeader,
  SheetFooter,
  SheetTitle,
  SheetDescription,
}

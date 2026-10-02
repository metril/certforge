"use client"

import * as React from "react"
import { cn } from "@/lib/utils"
import { Popover as PopoverPrimitive } from "radix-ui"

function Popover({
  ...props
}: React.ComponentProps<typeof PopoverPrimitive.Root>) {
  return <PopoverPrimitive.Root data-slot="popover" {...props} />
}

// C1: forwardRef so an `asChild` trigger (e.g. a Button) still gets a real
// DOM ref through this wrapper, and so PopoverTrigger itself can be given a
// ref by another component's Slot.
const PopoverTrigger = React.forwardRef<
  React.ComponentRef<typeof PopoverPrimitive.Trigger>,
  React.ComponentProps<typeof PopoverPrimitive.Trigger>
>(function PopoverTrigger({ ...props }, ref) {
  return <PopoverPrimitive.Trigger ref={ref} data-slot="popover-trigger" {...props} />
})
PopoverTrigger.displayName = "PopoverTrigger"

const PopoverContent = React.forwardRef<
  React.ComponentRef<typeof PopoverPrimitive.Content>,
  React.ComponentProps<typeof PopoverPrimitive.Content>
>(function PopoverContent({ className, align = "center", sideOffset = 4, ...props }, ref) {
  return (
    <PopoverPrimitive.Portal>
      <PopoverPrimitive.Content
        ref={ref}
        data-slot="popover-content"
        align={align}
        sideOffset={sideOffset}
        className={cn(
          "z-50 w-72 origin-(--radix-popover-content-transform-origin) rounded-md border bg-raised p-4 text-popover-foreground shadow-md outline-hidden data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2 data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=closed]:zoom-out-95 data-[state=open]:animate-in data-[state=open]:fade-in-0 data-[state=open]:zoom-in-95",
          className
        )}
        {...props}
      />
    </PopoverPrimitive.Portal>
  )
})
PopoverContent.displayName = "PopoverContent"

const PopoverAnchor = React.forwardRef<
  React.ComponentRef<typeof PopoverPrimitive.Anchor>,
  React.ComponentProps<typeof PopoverPrimitive.Anchor>
>(function PopoverAnchor({ ...props }, ref) {
  return <PopoverPrimitive.Anchor ref={ref} data-slot="popover-anchor" {...props} />
})
PopoverAnchor.displayName = "PopoverAnchor"

const PopoverHeader = React.forwardRef<
  React.ComponentRef<"div">,
  React.ComponentProps<"div">
>(function PopoverHeader({ className, ...props }, ref) {
  return (
    <div
      ref={ref}
      data-slot="popover-header"
      className={cn("flex flex-col gap-1 text-sm", className)}
      {...props}
    />
  )
})
PopoverHeader.displayName = "PopoverHeader"

const PopoverTitle = React.forwardRef<
  React.ComponentRef<"div">,
  React.ComponentProps<"h2">
>(function PopoverTitle({ className, ...props }, ref) {
  return (
    <div
      ref={ref}
      data-slot="popover-title"
      className={cn("font-medium", className)}
      {...props}
    />
  )
})
PopoverTitle.displayName = "PopoverTitle"

const PopoverDescription = React.forwardRef<
  React.ComponentRef<"p">,
  React.ComponentProps<"p">
>(function PopoverDescription({ className, ...props }, ref) {
  return (
    <p
      ref={ref}
      data-slot="popover-description"
      className={cn("text-muted-foreground", className)}
      {...props}
    />
  )
})
PopoverDescription.displayName = "PopoverDescription"

export {
  Popover,
  PopoverTrigger,
  PopoverContent,
  PopoverAnchor,
  PopoverHeader,
  PopoverTitle,
  PopoverDescription,
}

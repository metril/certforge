"use client"

import * as React from "react"
import { cn } from "@/lib/utils"
import { useInCard } from "@/components/Card"

const Table = React.forwardRef<
  React.ComponentRef<"table">,
  React.ComponentProps<"table">
>(function Table({ className, ...props }, ref) {
  const inCard = useInCard()
  return (
    <div
      data-slot="table-container"
      className={cn(
        "relative w-full overflow-x-auto",
        !inCard && "rounded-md border border-border bg-panel"
      )}
    >
      <table
        ref={ref}
        data-slot="table"
        className={cn("w-full caption-bottom text-sm", className)}
        {...props}
      />
    </div>
  )
})
Table.displayName = "Table"

const TableHeader = React.forwardRef<
  React.ComponentRef<"thead">,
  React.ComponentProps<"thead">
>(function TableHeader({ className, ...props }, ref) {
  return (
    <thead
      ref={ref}
      data-slot="table-header"
      className={cn("bg-subtle [&_tr]:border-b", className)}
      {...props}
    />
  )
})
TableHeader.displayName = "TableHeader"

const TableBody = React.forwardRef<
  React.ComponentRef<"tbody">,
  React.ComponentProps<"tbody">
>(function TableBody({ className, ...props }, ref) {
  return (
    <tbody
      ref={ref}
      data-slot="table-body"
      className={cn("[&_tr:last-child]:border-0", className)}
      {...props}
    />
  )
})
TableBody.displayName = "TableBody"

const TableFooter = React.forwardRef<
  React.ComponentRef<"tfoot">,
  React.ComponentProps<"tfoot">
>(function TableFooter({ className, ...props }, ref) {
  return (
    <tfoot
      ref={ref}
      data-slot="table-footer"
      className={cn(
        "border-t bg-muted/50 font-medium [&>tr]:last:border-b-0",
        className
      )}
      {...props}
    />
  )
})
TableFooter.displayName = "TableFooter"

const TableRow = React.forwardRef<
  React.ComponentRef<"tr">,
  React.ComponentProps<"tr">
>(function TableRow({ className, ...props }, ref) {
  return (
    <tr
      ref={ref}
      data-slot="table-row"
      className={cn(
        "group/row border-b transition-colors hover:bg-subtle/60 has-aria-expanded:bg-subtle/60 data-[state=selected]:bg-muted",
        className
      )}
      {...props}
    />
  )
})
TableRow.displayName = "TableRow"

const TableHead = React.forwardRef<
  React.ComponentRef<"th">,
  React.ComponentProps<"th">
>(function TableHead({ className, ...props }, ref) {
  return (
    <th
      ref={ref}
      data-slot="table-head"
      className={cn(
        "h-10 px-2 [&.sticky]:bg-subtle text-left align-middle text-xs font-medium whitespace-nowrap text-ink-muted [&:has([role=checkbox])]:pr-0 [&>[role=checkbox]]:translate-y-[2px]",
        className
      )}
      {...props}
    />
  )
})
TableHead.displayName = "TableHead"

const TableCell = React.forwardRef<
  React.ComponentRef<"td">,
  React.ComponentProps<"td">
>(function TableCell({ className, ...props }, ref) {
  return (
    <td
      ref={ref}
      data-slot="table-cell"
      className={cn(
        "p-2 align-middle whitespace-nowrap group-hover/row:[&.sticky]:bg-[color-mix(in_srgb,var(--cf-subtle)_60%,var(--cf-panel))] [&:has([role=checkbox])]:pr-0 [&>[role=checkbox]]:translate-y-[2px]",
        className
      )}
      {...props}
    />
  )
})
TableCell.displayName = "TableCell"

const TableCaption = React.forwardRef<
  React.ComponentRef<"caption">,
  React.ComponentProps<"caption">
>(function TableCaption({ className, ...props }, ref) {
  return (
    <caption
      ref={ref}
      data-slot="table-caption"
      className={cn("mt-4 text-sm text-muted-foreground", className)}
      {...props}
    />
  )
})
TableCaption.displayName = "TableCaption"

export {
  Table,
  TableHeader,
  TableBody,
  TableFooter,
  TableHead,
  TableRow,
  TableCell,
  TableCaption,
}

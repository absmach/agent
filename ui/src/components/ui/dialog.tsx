// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import { X } from "lucide-react";
import { type ComponentChildren, createContext } from "preact";
import type { HTMLAttributes } from "preact/compat";
import { useContext, useEffect, useState } from "preact/hooks";
import { cn } from "@/lib/utils";

interface DialogContext {
  open: boolean;
  setOpen: (v: boolean) => void;
}

const DialogCtx = createContext<DialogContext>({
  open: false,
  setOpen: () => {},
});

interface DialogProps {
  open?: boolean;
  onOpenChange?: (v: boolean) => void;
  children: ComponentChildren;
}

export function Dialog({
  open: controlledOpen,
  onOpenChange,
  children,
}: DialogProps) {
  const [internalOpen, setInternalOpen] = useState(false);
  const isControlled = controlledOpen !== undefined;
  const open = isControlled ? controlledOpen : internalOpen;

  function setOpen(v: boolean) {
    if (!isControlled) setInternalOpen(v);
    onOpenChange?.(v);
  }

  return (
    <DialogCtx.Provider value={{ open, setOpen }}>
      {children}
    </DialogCtx.Provider>
  );
}

export function DialogTrigger({
  children,
  ...props
}: HTMLAttributes<HTMLButtonElement>) {
  const { setOpen } = useContext(DialogCtx);
  return (
    <button type="button" onClick={() => setOpen(true)} {...props}>
      {children}
    </button>
  );
}

export function DialogContent({
  className,
  children,
  ...props
}: HTMLAttributes<HTMLDivElement>) {
  const { open, setOpen } = useContext(DialogCtx);

  useEffect(() => {
    if (!open) return;
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen(false);
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [open, setOpen]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <button
        type="button"
        aria-hidden="true"
        tabIndex={-1}
        className="fixed inset-0 bg-black/60 backdrop-blur-sm cursor-default"
        onClick={() => setOpen(false)}
      />
      <div
        role="dialog"
        aria-modal="true"
        className={cn(
          "relative z-50 w-full max-w-lg rounded-xl border bg-background p-6 shadow-lg",
          className,
        )}
        {...props}
      >
        <button
          type="button"
          onClick={() => setOpen(false)}
          className="absolute right-4 top-4 rounded-sm opacity-70 ring-offset-background transition-opacity hover:opacity-100"
        >
          <X className="h-4 w-4" />
          <span className="sr-only">Close</span>
        </button>
        {children}
      </div>
    </div>
  );
}

export function DialogHeader({
  className,
  ...props
}: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        "mb-4 flex flex-col gap-1.5 text-center sm:text-left",
        className,
      )}
      {...props}
    />
  );
}

export function DialogFooter({
  className,
  ...props
}: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        "mt-6 flex flex-col-reverse gap-2 sm:flex-row sm:justify-end",
        className,
      )}
      {...props}
    />
  );
}

export function DialogTitle({
  className,
  ...props
}: HTMLAttributes<HTMLHeadingElement>) {
  return (
    <h2
      className={cn(
        "text-lg font-semibold leading-none tracking-tight",
        className,
      )}
      {...props}
    />
  );
}

export function DialogDescription({
  className,
  ...props
}: HTMLAttributes<HTMLParagraphElement>) {
  return (
    <p className={cn("text-sm text-muted-foreground", className)} {...props} />
  );
}

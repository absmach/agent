// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import { Check, ChevronRight, Circle } from "lucide-react";
import { type ComponentChildren, createContext } from "preact";
import type { HTMLAttributes } from "preact/compat";
import { useContext, useEffect, useRef, useState } from "preact/hooks";
import { cn } from "@/lib/utils";

interface Coords {
  top: number;
  left: number;
  right: number;
}

interface DropdownCtx {
  open: boolean;
  setOpen: (v: boolean) => void;
  coords: Coords | null;
  setCoords: (c: Coords | null) => void;
}

const DropdownContext = createContext<DropdownCtx>({
  open: false,
  setOpen: () => {},
  coords: null,
  setCoords: () => {},
});

interface DropdownMenuProps {
  children: ComponentChildren;
}

export function DropdownMenu({ children }: DropdownMenuProps) {
  const [open, setOpen] = useState(false);
  const [coords, setCoords] = useState<Coords | null>(null);

  return (
    <DropdownContext.Provider value={{ open, setOpen, coords, setCoords }}>
      {children}
    </DropdownContext.Provider>
  );
}

export function DropdownMenuTrigger({
  children,
  ...props
}: HTMLAttributes<HTMLButtonElement>) {
  const { open, setOpen, setCoords } = useContext(DropdownContext);
  const ref = useRef<HTMLButtonElement>(null);

  return (
    <button
      ref={ref}
      type="button"
      aria-expanded={open}
      aria-haspopup="menu"
      onClick={(e) => {
        e.stopPropagation();
        if (!open && ref.current) {
          const rect = ref.current.getBoundingClientRect();
          setCoords({
            top: rect.bottom + 4,
            left: rect.left,
            right: window.innerWidth - rect.right,
          });
        }
        setOpen(!open);
      }}
      {...props}
    >
      {children}
    </button>
  );
}

interface DropdownMenuContentProps extends HTMLAttributes<HTMLDivElement> {
  align?: "start" | "end";
}

export function DropdownMenuContent({
  className,
  children,
  align = "end",
  ...props
}: DropdownMenuContentProps) {
  const { open, setOpen, coords } = useContext(DropdownContext);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    function onPointerDown(e: PointerEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen(false);
    }
    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [open, setOpen]);

  if (!open) return null;

  const style: Record<string, string> = coords
    ? {
        position: "fixed",
        top: `${coords.top}px`,
        ...(align === "end"
          ? { right: `${coords.right}px` }
          : { left: `${coords.left}px` }),
      }
    : {};

  return (
    <div
      ref={ref}
      role="menu"
      style={style}
      className={cn(
        "z-50 min-w-[8rem] overflow-hidden rounded-md border bg-popover p-1 text-popover-foreground shadow-md",
        className,
      )}
      {...props}
    >
      {children}
    </div>
  );
}

interface DropdownMenuItemProps extends HTMLAttributes<HTMLButtonElement> {
  inset?: boolean;
  variant?: "default" | "destructive";
}

export function DropdownMenuItem({
  className,
  inset,
  variant = "default",
  onClick,
  ...props
}: DropdownMenuItemProps) {
  const { setOpen } = useContext(DropdownContext);
  return (
    <button
      type="button"
      role="menuitem"
      className={cn(
        "relative flex w-full cursor-pointer select-none items-center gap-2 rounded-sm px-2 py-1.5 text-sm outline-none transition-colors focus:bg-accent focus:text-accent-foreground disabled:pointer-events-none disabled:opacity-50",
        inset && "pl-8",
        variant === "destructive" && "text-destructive focus:bg-destructive/10",
        className,
      )}
      onClick={(e) => {
        onClick?.(e);
        setOpen(false);
      }}
      {...props}
    />
  );
}

export function DropdownMenuLabel({
  className,
  ...props
}: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        "px-2 py-1.5 text-xs font-semibold text-muted-foreground",
        className,
      )}
      {...props}
    />
  );
}

export function DropdownMenuSeparator({
  className,
  ...props
}: HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={cn("-mx-1 my-1 h-px bg-border", className)} {...props} />
  );
}

interface DropdownMenuCheckboxItemProps
  extends HTMLAttributes<HTMLButtonElement> {
  checked?: boolean;
}

export function DropdownMenuCheckboxItem({
  className,
  checked = false,
  onClick,
  children,
  ...props
}: DropdownMenuCheckboxItemProps) {
  const { setOpen } = useContext(DropdownContext);
  return (
    <button
      type="button"
      role="menuitemcheckbox"
      aria-checked={checked}
      className={cn(
        "relative flex w-full cursor-pointer select-none items-center rounded-sm py-1.5 pl-8 pr-2 text-sm outline-none transition-colors focus:bg-accent focus:text-accent-foreground",
        className,
      )}
      onClick={(e) => {
        onClick?.(e);
        setOpen(false);
      }}
      {...props}
    >
      <span className="absolute left-2 flex size-3.5 items-center justify-center">
        {checked && <Check className="size-4" />}
      </span>
      {children}
    </button>
  );
}

export { ChevronRight, Circle };

// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import { type ComponentChildren, createContext } from "preact";
import { useContext, useId, useState } from "preact/hooks";
import { cn } from "@/lib/utils";

interface TooltipCtx {
  openTooltip: string | null;
  setOpenTooltip: (id: string | null) => void;
}

const TooltipContext = createContext<TooltipCtx>({
  openTooltip: null,
  setOpenTooltip: () => {},
});

export function TooltipProvider({ children }: { children: ComponentChildren }) {
  const [openTooltip, setOpenTooltip] = useState<string | null>(null);
  return (
    <TooltipContext.Provider value={{ openTooltip, setOpenTooltip }}>
      {children}
    </TooltipContext.Provider>
  );
}

interface TooltipProps {
  children: ComponentChildren;
  content: ComponentChildren;
  side?: "top" | "bottom";
  className?: string;
}

export function Tooltip({
  children,
  content,
  side = "top",
  className,
}: TooltipProps) {
  const rawId = useId();
  const id = `tt-${rawId.replace(/[:]/g, "")}`;
  const { openTooltip, setOpenTooltip } = useContext(TooltipContext);
  const isOpen = openTooltip === id;

  return (
    // biome-ignore lint/a11y/noStaticElementInteractions: tooltip wrapper needs hover/focus handlers to show/hide
    <span
      className="relative inline-flex"
      onMouseEnter={() => setOpenTooltip(id)}
      onMouseLeave={() => setOpenTooltip(null)}
      onFocus={() => setOpenTooltip(id)}
      onBlur={() => setOpenTooltip(null)}
    >
      {children}
      {isOpen && (
        <span
          role="tooltip"
          className={cn(
            "pointer-events-none absolute left-1/2 z-50 -translate-x-1/2 whitespace-nowrap rounded-md border bg-popover px-2.5 py-1.5 text-xs text-popover-foreground shadow-md",
            side === "top" ? "bottom-full mb-2" : "top-full mt-2",
            className,
          )}
        >
          {content}
        </span>
      )}
    </span>
  );
}

export type { TooltipProps };

// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import type { HTMLAttributes } from "preact/compat";
import { cn } from "@/lib/utils";

interface SeparatorProps extends HTMLAttributes<HTMLDivElement> {
  orientation?: "horizontal" | "vertical";
  decorative?: boolean;
}

export function Separator({
  className,
  orientation = "horizontal",
  decorative = true,
  ...props
}: SeparatorProps) {
  return (
    <div
      role={decorative ? "none" : "separator"}
      {...(decorative ? {} : { "aria-orientation": orientation })}
      className={cn(
        "shrink-0 bg-border",
        orientation === "horizontal" ? "h-px w-full" : "h-full w-px",
        className,
      )}
      {...props}
    />
  );
}

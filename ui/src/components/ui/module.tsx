// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import type { ComponentChildren } from "preact";
import type { HTMLAttributes } from "preact/compat";
import { cn } from "@/lib/utils";

interface ModuleProps extends HTMLAttributes<HTMLElement> {
  label: ComponentChildren;
  icon?: ComponentChildren;
  actions?: ComponentChildren;
  bodyClassName?: string;
}

/**
 * A labeled instrument panel: a hairline-bordered module with an uppercase
 * micro-label header. The instrument-panel alternative to a floating card.
 */
export function Module({
  label,
  icon,
  actions,
  className,
  bodyClassName,
  children,
  ...props
}: ModuleProps) {
  return (
    <section
      className={cn(
        "overflow-hidden rounded-md border bg-card text-card-foreground",
        className,
      )}
      {...props}
    >
      <header className="flex items-center justify-between gap-3 border-b bg-muted/35 px-4 py-2.5">
        <div className="flex items-center gap-2">
          {icon && <span className="text-muted-foreground">{icon}</span>}
          <span className="label-eyebrow">{label}</span>
        </div>
        {actions && <div className="flex items-center gap-1.5">{actions}</div>}
      </header>
      <div className={cn("p-4", bodyClassName)}>{children}</div>
    </section>
  );
}

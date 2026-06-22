// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import type { ComponentChildren } from "preact";
import type { HTMLAttributes } from "preact/compat";
import { cn } from "@/lib/utils";

interface EmptyStateProps extends HTMLAttributes<HTMLDivElement> {
  icon?: ComponentChildren;
  title: string;
  description?: ComponentChildren;
  action?: ComponentChildren;
}

export function EmptyState({
  icon,
  title,
  description,
  action,
  className,
  ...props
}: EmptyStateProps) {
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center py-11 text-center text-muted-foreground",
        className,
      )}
      {...props}
    >
      {icon && <div className="mb-2.5 text-muted-foreground/40">{icon}</div>}
      <h3 className="mb-1 text-sm font-semibold text-foreground">{title}</h3>
      {description && (
        <p className="max-w-xs text-xs text-muted-foreground">{description}</p>
      )}
      {action && <div className="mt-3">{action}</div>}
    </div>
  );
}

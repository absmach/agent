// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import type { HTMLAttributes } from "preact/compat";
import { cn } from "@/lib/utils";

export function Skeleton({
  className,
  ...props
}: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn("animate-pulse rounded-md bg-muted", className)}
      {...props}
    />
  );
}

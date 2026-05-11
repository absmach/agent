// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import { cn } from "@/lib/utils";
import type { LabelHTMLAttributes } from "preact/compat";

export function Label({
  className,
  ...props
}: LabelHTMLAttributes<HTMLLabelElement>) {
  return (
    <label
      className={cn(
        "text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70",
        className,
      )}
      {...props}
    />
  );
}

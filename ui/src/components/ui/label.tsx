// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import type { LabelHTMLAttributes } from "preact/compat";
import { cn } from "@/lib/utils";

export function Label({
  className,
  ...props
}: LabelHTMLAttributes<HTMLLabelElement>) {
  return (
    // biome-ignore lint/a11y/noLabelWithoutControl: this primitive receives htmlFor from callers.
    <label
      className={cn(
        "text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70",
        className,
      )}
      {...props}
    />
  );
}

// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import type { ComponentChildren } from "preact";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { cn } from "@/lib/utils";

interface ErrorAlertProps {
  error: ComponentChildren;
  className?: string;
}

export function ErrorAlert({ error, className }: ErrorAlertProps) {
  if (!error) return null;
  return (
    <Alert variant="destructive" className={cn(className)}>
      <AlertDescription>{error}</AlertDescription>
    </Alert>
  );
}

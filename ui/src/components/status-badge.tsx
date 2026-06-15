// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import type { ComponentChildren } from "preact";
import type { HTMLAttributes } from "preact/compat";
import { Badge, type BadgeProps } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

export type StatusValue =
  | "online"
  | "offline"
  | "active"
  | "inactive"
  | "pending"
  | "checking"
  | "pass"
  | "fail"
  | "running"
  | "stopped"
  | "unknown"
  | "enabled"
  | "disabled"
  | "triggered"
  | "error";

interface StatusConfig {
  variant: BadgeProps["variant"];
  dot?: string;
}

const statusMap: Record<string, StatusConfig> = {
  online: { variant: "success" },
  offline: { variant: "destructive" },
  active: { variant: "success" },
  inactive: { variant: "muted" },
  pending: { variant: "warning" },
  checking: { variant: "muted" },
  pass: { variant: "success" },
  fail: { variant: "destructive" },
  running: { variant: "default" },
  stopped: { variant: "destructive" },
  unknown: { variant: "warning" },
  enabled: { variant: "success" },
  disabled: { variant: "muted" },
  triggered: { variant: "success" },
  error: { variant: "destructive" },
};

interface StatusBadgeProps
  extends Omit<HTMLAttributes<HTMLSpanElement>, "title"> {
  status: StatusValue;
  label?: string;
  dot?: boolean;
  pulse?: boolean;
}

export function StatusBadge({
  status,
  label,
  dot = true,
  pulse = false,
  className,
  ...props
}: StatusBadgeProps) {
  const config = statusMap[status] ?? statusMap.unknown;
  const text = label ?? status.charAt(0).toUpperCase() + status.slice(1);

  return (
    <Badge variant={config.variant} className={cn(className)} {...props}>
      {dot && (
        <span
          className={cn(
            "inline-block size-1.5 rounded-full bg-current",
            pulse && "animate-pulse",
          )}
        />
      )}
      {text}
    </Badge>
  );
}

export type { ComponentChildren };

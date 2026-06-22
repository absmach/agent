// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import { Moon, PanelLeft, Sun } from "lucide-react";
import { useLocation } from "preact-iso";
import {
  useAgentStatus,
  useClock,
  useDeviceCount,
  useTheme,
} from "@/lib/agent";
import { cn } from "@/lib/utils";
import { UI_BASE } from "@/routes";
import { isActivePath, navGroups } from "./nav";
import { useSidebar } from "./sidebar-context";

function sectionLabel(path: string): string {
  for (const group of navGroups) {
    for (const item of group.items) {
      if (isActivePath(path, item.href)) return item.label;
    }
  }
  return "";
}

function Vital({
  label,
  children,
  className,
}: {
  label: string;
  children: preact.ComponentChildren;
  className?: string;
}) {
  return (
    <span className={cn("flex items-center gap-1.5", className)}>
      <span className="label-eyebrow">{label}</span>
      <span className="font-mono text-xs text-foreground">{children}</span>
    </span>
  );
}

export function Header() {
  const { path } = useLocation();
  const { toggleCollapsed, setMobileOpen } = useSidebar();
  const { dark, toggle } = useTheme();
  const status = useAgentStatus();
  const { count, online } = useDeviceCount();
  const now = useClock();

  const section = sectionLabel(path);
  const linkClass =
    status === "online"
      ? "text-success"
      : status === "offline"
        ? "text-destructive"
        : "text-warning";

  function onTrigger() {
    if (typeof window !== "undefined" && window.innerWidth < 1024) {
      setMobileOpen(true);
    } else {
      toggleCollapsed();
    }
  }

  return (
    <header className="sticky top-0 z-10 flex h-14 items-center gap-2 border-b border-border bg-background/90 px-4 backdrop-blur-sm sm:px-6">
      <button
        type="button"
        onClick={onTrigger}
        className="flex size-8 shrink-0 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
        aria-label="Toggle sidebar"
        title="Toggle sidebar (⌘B)"
      >
        <PanelLeft className="size-4.5" />
      </button>

      <span className="h-5 w-px shrink-0 bg-border" aria-hidden="true" />

      {/* Breadcrumb */}
      <nav aria-label="Breadcrumb" className="flex min-w-0 items-center gap-2">
        <a
          href={`${UI_BASE}/`}
          className="hidden shrink-0 text-sm text-muted-foreground no-underline transition-colors hover:text-foreground sm:inline"
        >
          Agent
        </a>
        <span
          className="hidden text-muted-foreground/40 sm:inline"
          aria-hidden="true"
        >
          /
        </span>
        <span className="truncate text-sm font-medium text-foreground">
          {section || "Overview"}
        </span>
      </nav>

      {/* Live vitals */}
      <div className="ml-auto flex items-center gap-3 sm:gap-4">
        <Vital label="Link">
          <span className={cn("flex items-center gap-1.5", linkClass)}>
            <span className="inline-block size-1.5 rounded-full bg-current" />
            {status === "online"
              ? "ONLINE"
              : status === "offline"
                ? "OFFLINE"
                : "···"}
          </span>
        </Vital>
        <Vital label="Devices" className="hidden md:flex">
          {count === null ? (
            "—"
          ) : (
            <span>
              <span className="text-success">{online}</span>
              <span className="text-muted-foreground">/{count}</span>
            </span>
          )}
        </Vital>
        <span className="hidden font-mono text-xs tabular-nums text-muted-foreground lg:inline">
          {now.toLocaleTimeString([], { hour12: false })}
        </span>
        <button
          type="button"
          onClick={toggle}
          className="flex size-8 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
          aria-label="Toggle color theme"
          title="Toggle theme"
        >
          {dark ? <Sun className="size-4" /> : <Moon className="size-4" />}
        </button>
      </div>
    </header>
  );
}

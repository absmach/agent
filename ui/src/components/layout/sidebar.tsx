// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import { Cpu, X } from "lucide-react";
import { useLocation } from "preact-iso";
import { useAgentInfo } from "@/lib/agent";
import { cn } from "@/lib/utils";
import { UI_BASE } from "@/routes";
import { isActivePath, navGroups } from "./nav";
import { useSidebar } from "./sidebar-context";

function RailBody({ onNavigate }: { onNavigate?: () => void }) {
  const { path } = useLocation();
  const info = useAgentInfo();

  return (
    <div className="flex h-full flex-col">
      {/* Brand */}
      <a
        href={`${UI_BASE}/`}
        onClick={onNavigate}
        className="flex h-14 items-center gap-2 border-b border-sidebar-border px-5 no-underline"
      >
        <img
          src={`${UI_BASE}/magistrala-logo.svg`}
          alt="Magistrala"
          className="h-6 w-auto brightness-0 invert"
        />
        <span className="rounded bg-sidebar-accent px-1.5 py-0.5 font-mono text-[0.625rem] font-medium uppercase tracking-wide text-sidebar-foreground/80">
          Agent
        </span>
      </a>

      {/* Nav */}
      <nav className="flex-1 overflow-y-auto px-3 py-4">
        {navGroups.map((group) => (
          <div key={group.label} className="mb-5 last:mb-0">
            <div className="px-2 pb-1.5 text-[0.6875rem] font-semibold uppercase tracking-[0.08em] text-sidebar-foreground/45">
              {group.label}
            </div>
            <ul className="flex flex-col gap-0.5">
              {group.items.map(({ href, label, icon: Icon }) => {
                const active = isActivePath(path, href);
                return (
                  <li key={href}>
                    <a
                      href={href}
                      onClick={onNavigate}
                      aria-current={active ? "page" : undefined}
                      className={cn(
                        "group flex items-center gap-2.5 rounded-md px-2.5 py-2 text-sm no-underline transition-colors",
                        active
                          ? "bg-sidebar-accent font-medium text-sidebar-foreground"
                          : "text-sidebar-foreground/65 hover:bg-sidebar-hover hover:text-sidebar-foreground",
                      )}
                    >
                      <Icon
                        className={cn(
                          "size-4 shrink-0 transition-colors",
                          active
                            ? "text-sidebar-foreground"
                            : "text-sidebar-foreground/50 group-hover:text-sidebar-foreground",
                        )}
                      />
                      {label}
                    </a>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </nav>

      {/* Footer identity */}
      <div className="p-3">
        <div className="flex items-center gap-2.5 rounded-md border border-sidebar-border bg-sidebar-hover px-2.5 py-2">
          <span className="flex size-8 shrink-0 items-center justify-center rounded-md bg-sidebar-accent text-sidebar-foreground">
            <Cpu className="size-4" />
          </span>
          <span className="flex min-w-0 flex-col leading-tight">
            <span className="truncate text-xs font-medium text-sidebar-foreground">
              {info?.instance_id
                ? `node-${info.instance_id.slice(0, 8)}`
                : "this gateway"}
            </span>
            <span className="truncate font-mono text-[0.6875rem] text-sidebar-foreground/55">
              {info?.version ? `fw ${info.version}` : "agent"}
            </span>
          </span>
        </div>
      </div>
    </div>
  );
}

export function Sidebar() {
  const { collapsed, mobileOpen, setMobileOpen } = useSidebar();

  return (
    <>
      {/* Desktop rail (offcanvas collapse) */}
      <aside
        data-collapsed={collapsed}
        className={cn(
          "fixed inset-y-0 left-0 z-20 hidden w-64 bg-sidebar text-sidebar-foreground transition-transform duration-300 ease-out lg:block",
          collapsed && "-translate-x-full",
        )}
      >
        <RailBody />
      </aside>

      {/* Mobile drawer */}
      {mobileOpen && (
        <div className="fixed inset-0 z-50 lg:hidden">
          <button
            type="button"
            aria-label="Close navigation"
            onClick={() => setMobileOpen(false)}
            className="absolute inset-0 bg-black/50 backdrop-blur-[1px]"
          />
          <div className="absolute inset-y-0 left-0 w-64 bg-sidebar text-sidebar-foreground shadow-xl">
            <button
              type="button"
              onClick={() => setMobileOpen(false)}
              className="absolute right-2 top-4 flex size-8 items-center justify-center rounded-md text-sidebar-foreground/70 hover:bg-sidebar-hover hover:text-sidebar-foreground"
              aria-label="Close navigation"
            >
              <X className="size-4" />
            </button>
            <RailBody onNavigate={() => setMobileOpen(false)} />
          </div>
        </div>
      )}
    </>
  );
}

// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import { cn } from "@/lib/utils";
import { Activity, Bot, Home, Network, Settings, Terminal } from "lucide-react";
import { useLocation } from "preact-iso";

const navItems = [
  { href: "/", label: "Home", icon: Home },
  { href: "/config", label: "Configuration", icon: Settings },
  { href: "/nodered", label: "Node-RED", icon: Network },
  { href: "/services", label: "Services", icon: Activity },
  { href: "/exec", label: "Execute", icon: Terminal },
];

interface SidebarProps {
  isOpen: boolean;
}

export function Sidebar({ isOpen }: SidebarProps) {
  const { path } = useLocation();

  return (
    <aside
      style={{
        width: isOpen ? "var(--sidebar-width)" : "0",
        minWidth: isOpen ? "var(--sidebar-width)" : "0",
        background: "var(--sidebar-bg)",
        color: "var(--sidebar-fg)",
      }}
      className="flex h-full flex-col overflow-hidden transition-all duration-300"
    >
      {/* Logo */}
      <div className="flex h-[var(--topbar-height)] shrink-0 items-center gap-2.5 border-b border-white/10 px-4">
        <div className="flex h-7 w-7 items-center justify-center rounded-md bg-white/15">
          <Bot className="h-4 w-4" />
        </div>
        <span className="whitespace-nowrap text-sm font-semibold tracking-tight">
          Magistrala Agent
        </span>
      </div>

      {/* Nav */}
      <nav className="flex flex-col gap-1 p-3">
        <p
          className="mb-1 mt-2 px-2 text-[10px] font-semibold uppercase tracking-widest whitespace-nowrap"
          style={{ color: "var(--sidebar-section)" }}
        >
          Management
        </p>
        {navItems.map(({ href, label, icon: Icon }) => {
          const active =
            href === "/" ? path === "/" : path.startsWith(href);
          return (
            <a
              key={href}
              href={href}
              style={
                active
                  ? {
                      background: "var(--sidebar-active-bg)",
                      color: "var(--sidebar-fg)",
                    }
                  : {}
              }
              className={cn(
                "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium whitespace-nowrap transition-colors",
                active ? "font-semibold" : "opacity-80 hover:opacity-100",
              )}
              onMouseEnter={(e) => {
                if (!active)
                  (e.currentTarget as HTMLAnchorElement).style.background =
                    "var(--sidebar-hover-bg)";
              }}
              onMouseLeave={(e) => {
                if (!active)
                  (e.currentTarget as HTMLAnchorElement).style.background = "";
              }}
            >
              <Icon className="h-4 w-4 shrink-0" />
              {label}
            </a>
          );
        })}
      </nav>

      {/* Footer */}
      <div
        className="mt-auto border-t border-white/10 px-4 py-3"
        style={{ color: "var(--sidebar-section)" }}
      >
        <p className="whitespace-nowrap text-xs">Magistrala Agent v1.0</p>
      </div>
    </aside>
  );
}

// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import {
  Activity,
  Home,
  Moon,
  Network,
  Settings,
  Sun,
  Terminal,
  Zap,
} from "lucide-react";
import { useEffect, useState } from "preact/hooks";
import { useLocation } from "preact-iso";
import { cn } from "@/lib/utils";
import { UI_BASE } from "@/routes";

const navItems = [
  { href: `${UI_BASE}/`, label: "Home", icon: Home },
  { href: `${UI_BASE}/config`, label: "Configuration", icon: Settings },
  { href: `${UI_BASE}/nodered`, label: "Node-RED", icon: Network },
  { href: `${UI_BASE}/services`, label: "Services", icon: Activity },
  { href: `${UI_BASE}/exec`, label: "Execute", icon: Terminal },
];

type Status = "checking" | "online" | "offline";

export function Topbar() {
  const { path } = useLocation();
  const [status, setStatus] = useState<Status>("checking");
  const [dark, setDark] = useState(false);

  useEffect(() => {
    const saved = localStorage.getItem("agent-ui-theme");
    const useDark =
      saved === "dark" ||
      (!saved && window.matchMedia("(prefers-color-scheme: dark)").matches);
    setDark(useDark);
    document.documentElement.classList.toggle("dark", useDark);
    document.documentElement.dataset.theme = useDark ? "dark" : "light";
  }, []);

  useEffect(() => {
    async function check() {
      try {
        const res = await fetch("/config", {
          cache: "no-store",
          signal: AbortSignal.timeout(3000),
        });
        setStatus(res.ok ? "online" : "offline");
      } catch {
        setStatus("offline");
      }
    }
    check();
    const id = setInterval(check, 5000);
    return () => clearInterval(id);
  }, []);

  function toggleTheme() {
    const next = !dark;
    setDark(next);
    localStorage.setItem("agent-ui-theme", next ? "dark" : "light");
    document.documentElement.classList.toggle("dark", next);
    document.documentElement.dataset.theme = next ? "dark" : "light";
  }

  const isOnline = status === "online";

  return (
    <nav className="sticky top-0 z-50 flex h-[52px] items-stretch border-b border-[var(--nav-border)] bg-[var(--nav-bg)] px-3 sm:px-5">
      <a
        href={`${UI_BASE}/`}
        className="mr-4 flex shrink-0 items-center gap-2.5 text-white no-underline sm:mr-6"
      >
        <span className="flex h-7 w-7 items-center justify-center rounded-md bg-primary">
          <Zap className="h-4 w-4" />
        </span>
        <span className="hidden text-sm font-semibold tracking-tight sm:inline">
          Magistrala Agent
        </span>
      </a>

      <div className="flex min-w-0 flex-1 items-stretch gap-px overflow-x-auto">
        {navItems.map(({ href, label, icon: Icon }) => {
          const active =
            href === `${UI_BASE}/`
              ? path === UI_BASE || path === `${UI_BASE}/`
              : path.startsWith(href);

          return (
            <a
              key={href}
              href={href}
              className={cn(
                "flex items-center gap-1.5 whitespace-nowrap border-b-2 border-transparent px-3 text-[0.8rem] font-medium text-white/55 transition-colors hover:text-white/85",
                active && "border-primary text-white",
              )}
            >
              <Icon className="h-3.5 w-3.5 shrink-0 opacity-80" />
              <span className="hidden sm:inline">{label}</span>
            </a>
          );
        })}
      </div>

      <div className="ml-auto flex items-center gap-2.5 pl-3">
        <div
          className={cn(
            "flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[0.7rem] font-semibold",
            isOnline
              ? "bg-emerald-500/15 text-emerald-300"
              : "bg-red-500/15 text-red-300",
          )}
        >
          <span
            className={cn(
              "h-1.5 w-1.5 rounded-full bg-current",
              status === "checking" && "animate-pulse",
            )}
          />
          <span>{isOnline ? "Connected" : "Disconnected"}</span>
        </div>
        <button
          type="button"
          onClick={toggleTheme}
          className="flex h-[30px] w-[30px] items-center justify-center rounded-md bg-white/10 text-white/65 transition-colors hover:bg-white/15 hover:text-white"
          title="Toggle theme"
          aria-label="Toggle theme"
        >
          {dark ? (
            <Sun className="h-3.5 w-3.5" />
          ) : (
            <Moon className="h-3.5 w-3.5" />
          )}
        </button>
      </div>
    </nav>
  );
}

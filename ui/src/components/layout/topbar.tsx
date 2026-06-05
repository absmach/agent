// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import {
  Activity,
  Cpu,
  Download,
  Home,
  Menu,
  Moon,
  Network,
  ScrollText,
  Settings,
  Sun,
  Terminal,
  X,
  Zap,
} from "lucide-react";
import { useEffect, useRef, useState } from "preact/hooks";
import { useLocation } from "preact-iso";
import { cn } from "@/lib/utils";
import { UI_BASE } from "@/routes";

const navItems = [
  { href: `${UI_BASE}/`, label: "Home", icon: Home },
  { href: `${UI_BASE}/config`, label: "Configuration", icon: Settings },
  { href: `${UI_BASE}/devices`, label: "Devices", icon: Cpu },
  { href: `${UI_BASE}/nodered`, label: "Node-RED", icon: Network },
  { href: `${UI_BASE}/services`, label: "Services", icon: Activity },
  { href: `${UI_BASE}/exec`, label: "Execute", icon: Terminal },
  { href: `${UI_BASE}/ota`, label: "OTA", icon: Download },
  { href: `${UI_BASE}/logs`, label: "Logs", icon: ScrollText },
];

type Status = "checking" | "online" | "offline";

export function Topbar() {
  const { path } = useLocation();
  const [status, setStatus] = useState<Status>("checking");
  const [dark, setDark] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

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

  // Close the mobile menu when navigating.
  useEffect(() => {
    setMenuOpen(false);
  }, [path]);

  // Close the mobile menu when clicking outside.
  useEffect(() => {
    if (!menuOpen) return;
    function onPointerDown(e: PointerEvent) {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setMenuOpen(false);
      }
    }
    document.addEventListener("pointerdown", onPointerDown);
    return () => document.removeEventListener("pointerdown", onPointerDown);
  }, [menuOpen]);

  function toggleTheme() {
    const next = !dark;
    setDark(next);
    localStorage.setItem("agent-ui-theme", next ? "dark" : "light");
    document.documentElement.classList.toggle("dark", next);
    document.documentElement.dataset.theme = next ? "dark" : "light";
  }

  function isActive(href: string) {
    return href === `${UI_BASE}/`
      ? path === UI_BASE || path === `${UI_BASE}/`
      : path.startsWith(href);
  }

  const isOnline = status === "online";

  return (
    <div ref={menuRef} className="sticky top-0 z-50">
      {/* Main bar */}
      <nav className="flex h-[52px] items-stretch border-b border-[var(--nav-border)] bg-[var(--nav-bg)] px-3 sm:px-5">
        {/* Logo */}
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

        {/* Desktop nav — hidden below lg */}
        <div className="hidden flex-1 items-stretch gap-px lg:flex">
          {navItems.map(({ href, label, icon: Icon }) => (
            <a
              key={href}
              href={href}
              className={cn(
                "flex items-center gap-1.5 whitespace-nowrap border-b-2 border-transparent px-3 text-[0.8rem] font-medium text-white/55 transition-colors hover:text-white/85",
                isActive(href) && "border-primary text-white",
              )}
            >
              <Icon className="h-3.5 w-3.5 shrink-0 opacity-80" />
              {label}
            </a>
          ))}
        </div>

        {/* Right side: status + theme + hamburger */}
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
            <span className="hidden xs:inline">
              {isOnline ? "Connected" : "Disconnected"}
            </span>
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

          {/* Hamburger — visible below lg */}
          <button
            type="button"
            onClick={() => setMenuOpen((o) => !o)}
            className="flex h-[30px] w-[30px] items-center justify-center rounded-md bg-white/10 text-white/65 transition-colors hover:bg-white/15 hover:text-white lg:hidden"
            aria-label="Toggle menu"
          >
            {menuOpen ? (
              <X className="h-4 w-4" />
            ) : (
              <Menu className="h-4 w-4" />
            )}
          </button>
        </div>
      </nav>

      {/* Mobile dropdown */}
      {menuOpen && (
        <div className="absolute inset-x-0 top-full border-b border-[var(--nav-border)] bg-[var(--nav-bg)] shadow-lg lg:hidden">
          {navItems.map(({ href, label, icon: Icon }) => (
            <a
              key={href}
              href={href}
              className={cn(
                "flex items-center gap-3 border-l-2 border-transparent px-5 py-3 text-[0.85rem] font-medium text-white/60 transition-colors hover:bg-white/5 hover:text-white/90",
                isActive(href) && "border-primary bg-white/5 text-white",
              )}
            >
              <Icon className="h-4 w-4 shrink-0" />
              {label}
            </a>
          ))}
        </div>
      )}
    </div>
  );
}

// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import { PanelLeft } from "lucide-react";
import { useLocation } from "preact-iso";

const titles: Record<string, string> = {
  "/": "Home",
  "/config": "Configuration",
  "/nodered": "Node-RED",
  "/services": "Services",
  "/exec": "Execute Command",
};

interface TopbarProps {
  onToggle: () => void;
}

export function Topbar({ onToggle }: TopbarProps) {
  const { path } = useLocation();
  const title = titles[path] ?? "Magistrala Agent";

  return (
    <header
      className="flex shrink-0 items-center gap-3 border-b bg-card px-4"
      style={{ height: "var(--topbar-height)" }}
    >
      <button
        type="button"
        onClick={onToggle}
        className="rounded-md p-1.5 text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
        aria-label="Toggle sidebar"
      >
        <PanelLeft className="h-5 w-5" />
      </button>

      <span className="text-sm font-medium text-foreground">{title}</span>
    </header>
  );
}

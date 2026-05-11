// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import type { ComponentChildren } from "preact";
import { useState } from "preact/hooks";
import { Sidebar } from "./sidebar";
import { Topbar } from "./topbar";

export function Shell({ children }: { children: ComponentChildren }) {
  const [sidebarOpen, setSidebarOpen] = useState(true);

  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar isOpen={sidebarOpen} />
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar onToggle={() => setSidebarOpen((o) => !o)} />
        <main className="flex-1 overflow-y-auto p-6">{children}</main>
      </div>
    </div>
  );
}

// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import type { ComponentChildren } from "preact";
import { Topbar } from "./topbar";

export function Shell({ children }: { children: ComponentChildren }) {
  return (
    <div className="min-h-screen bg-background text-foreground">
      <Topbar />
      <main className="mx-auto max-w-[1060px] px-4 py-7 sm:px-6 lg:px-8">
        {children}
      </main>
    </div>
  );
}

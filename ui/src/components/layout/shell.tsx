// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import type { ComponentChildren } from "preact";
import { ToastProvider } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { Topbar } from "./topbar";

export function Shell({ children }: { children: ComponentChildren }) {
  return (
    <ToastProvider>
      <TooltipProvider>
        <div className="min-h-screen bg-background text-foreground">
          <Topbar />
          <main className="mx-auto max-w-265 px-4 py-7 sm:px-6 lg:px-8">
            {children}
          </main>
        </div>
      </TooltipProvider>
    </ToastProvider>
  );
}

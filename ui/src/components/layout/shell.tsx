// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import type { ComponentChildren } from "preact";
import { ToastProvider } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";
import { Header } from "./header";
import { Sidebar } from "./sidebar";
import { SidebarProvider, useSidebar } from "./sidebar-context";

function Frame({ children }: { children: ComponentChildren }) {
  const { collapsed } = useSidebar();
  return (
    <div className="min-h-screen bg-background text-foreground">
      <Sidebar />
      <div
        className={cn(
          "transition-[padding] duration-300 ease-out",
          collapsed ? "lg:pl-0" : "lg:pl-64",
        )}
      >
        <Header />
        <main className="mx-auto max-w-300 px-4 pb-16 pt-6 sm:px-6 lg:px-8">
          {children}
        </main>
      </div>
    </div>
  );
}

export function Shell({ children }: { children: ComponentChildren }) {
  return (
    <SidebarProvider>
      <ToastProvider>
        <TooltipProvider>
          <Frame>{children}</Frame>
        </TooltipProvider>
      </ToastProvider>
    </SidebarProvider>
  );
}

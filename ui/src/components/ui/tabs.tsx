// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import { type ComponentChildren, createContext } from "preact";
import type { HTMLAttributes } from "preact/compat";
import { useContext } from "preact/hooks";
import { cn } from "@/lib/utils";

interface TabsContext {
  value: string;
  setValue: (v: string) => void;
}

interface TabsProps {
  value?: string;
  defaultValue?: string;
  onValueChange?: (v: string) => void;
  children: ComponentChildren;
  className?: string;
}

const TabsCtx = createContext<TabsContext>({
  value: "",
  setValue: () => {},
});

export function Tabs({
  value: controlled,
  defaultValue,
  onValueChange,
  children,
  className,
}: TabsProps) {
  const current = controlled ?? defaultValue ?? "";

  function setValue(v: string) {
    onValueChange?.(v);
  }

  return (
    <TabsCtx.Provider value={{ value: current, setValue }}>
      <div className={className}>{children}</div>
    </TabsCtx.Provider>
  );
}

interface TabsListProps extends HTMLAttributes<HTMLDivElement> {}

export function TabsList({ className, ...props }: TabsListProps) {
  return (
    <div
      role="tablist"
      className={cn(
        "inline-flex h-9 items-center justify-center rounded-lg bg-muted p-1 text-muted-foreground",
        className,
      )}
      {...props}
    />
  );
}

interface TabsTriggerProps extends HTMLAttributes<HTMLButtonElement> {
  value: string;
}

export function TabsTrigger({ className, value, ...props }: TabsTriggerProps) {
  const ctx = useContext(TabsCtx);
  const isActive = ctx.value === value;

  return (
    <button
      type="button"
      role="tab"
      aria-selected={isActive}
      onClick={() => ctx.setValue(value)}
      className={cn(
        "inline-flex items-center justify-center whitespace-nowrap rounded-md px-3 py-1 text-sm font-medium ring-offset-background transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50",
        isActive
          ? "bg-background text-foreground shadow"
          : "hover:text-foreground",
        className,
      )}
      {...props}
    />
  );
}

interface TabsContentProps extends HTMLAttributes<HTMLDivElement> {
  value: string;
}

export function TabsContent({ className, value, ...props }: TabsContentProps) {
  const ctx = useContext(TabsCtx);
  if (ctx.value !== value) return null;

  return (
    <div
      role="tabpanel"
      className={cn(
        "mt-2 ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2",
        className,
      )}
      {...props}
    />
  );
}

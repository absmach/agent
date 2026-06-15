// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import { ChevronRight, RefreshCw } from "lucide-react";
import { useEffect, useState } from "preact/hooks";
import { CommitLink } from "@/components/commit-link";
import { navGroups } from "@/components/layout/nav";
import { PageHeader } from "@/components/page-header";
import { Button } from "@/components/ui/button";
import { Module } from "@/components/ui/module";
import { Skeleton } from "@/components/ui/skeleton";
import { useAgentStatus } from "@/lib/agent";
import { cn, formatDuration } from "@/lib/utils";
import { UI_BASE } from "@/routes";

interface Health {
  status?: string;
  version?: string;
  commit?: string;
  build_time?: string;
  instance_id?: string;
  description?: string;
}

interface Runtime {
  log_level?: string;
  heartbeat_interval?: string;
  telemetry_interval?: string;
  terminal_session_timeout?: string;
  bs_valid?: string;
}

interface TelemetryCfg {
  interval?: string;
  include_temperature?: boolean;
  include_network?: boolean;
  include_load?: boolean;
}

const descriptions: Record<string, string> = {
  [`${UI_BASE}/telemetry`]: "Uptime, memory, CPU, disk, and load readers",
  [`${UI_BASE}/health`]: "Supervisor status and systemd watchdog",
  [`${UI_BASE}/services`]: "Local service heartbeat registry",
  [`${UI_BASE}/logs`]: "Recent agent log output",
  [`${UI_BASE}/devices`]: "Downstream serial, I2C, and Modbus devices",
  [`${UI_BASE}/exec`]: "Run allowlisted shell commands",
  [`${UI_BASE}/terminal`]: "Interactive PTY session over the agent",
  [`${UI_BASE}/nodered`]: "Flows, deploy, and runtime state",
  [`${UI_BASE}/config`]: "Inspect and edit runtime configuration",
  [`${UI_BASE}/ota`]: "Over-the-air binary updates",
  [`${UI_BASE}/bootstrap`]: "Provisioning profile and cache",
};

function fmtBuild(iso?: string): string {
  if (!iso || iso.startsWith("0001")) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleDateString([], {
    year: "numeric",
    month: "short",
    day: "2-digit",
  });
}

function Field({
  label,
  value,
  mono = true,
  className,
}: {
  label: string;
  value: preact.ComponentChildren;
  mono?: boolean;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-col gap-1", className)}>
      <span className="label-eyebrow">{label}</span>
      <span
        className={cn(
          "truncate text-sm text-foreground",
          mono && "font-mono text-[0.8125rem]",
        )}
      >
        {value}
      </span>
    </div>
  );
}

export function HomePage() {
  const status = useAgentStatus();
  const [health, setHealth] = useState<Health | null>(null);
  const [runtime, setRuntime] = useState<Runtime | null>(null);
  const [telemetry, setTelemetry] = useState<TelemetryCfg | null>(null);
  const [loading, setLoading] = useState(true);

  async function load() {
    setLoading(true);
    const [h, c, r] = await Promise.allSettled([
      fetch("/health", { cache: "no-store" }).then((x) => x.json()),
      fetch("/config", { cache: "no-store" }).then((x) => x.json()),
      fetch("/config/runtime", { cache: "no-store" }).then((x) => x.json()),
    ]);
    if (h.status === "fulfilled") setHealth(h.value);
    if (c.status === "fulfilled") setTelemetry(c.value?.telemetry ?? {});
    if (r.status === "fulfilled") setRuntime(r.value?.config ?? r.value ?? {});
    setLoading(false);
  }

  useEffect(() => {
    load();
  }, []);

  const online = status === "online";
  const healthy = health?.status && /pass|ok|up|healthy/i.test(health.status);

  const haveCfg = telemetry !== null;
  const readers = [
    { label: "Temp", on: haveCfg && telemetry?.include_temperature !== false },
    { label: "Network", on: haveCfg && telemetry?.include_network !== false },
    { label: "Load", on: haveCfg && telemetry?.include_load !== false },
  ];

  return (
    <div className="flex flex-col gap-5">
      <PageHeader
        title="Overview"
        subtitle="Live status and controls for this gateway agent."
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={loading}>
            <RefreshCw className={cn("size-3.5", loading && "animate-spin")} />
            Refresh
          </Button>
        }
      />

      {/* Gateway identity + link state */}
      <Module label="Gateway">
        <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_2fr] lg:gap-8">
          {/* Link state */}
          <div className="flex flex-col gap-3 border-b border-border pb-5 lg:border-b-0 lg:border-r lg:pb-0 lg:pr-8">
            <div className="flex items-center gap-2.5">
              <span className="relative flex size-2.5">
                {online && (
                  <span className="absolute inline-flex size-full animate-ping rounded-full bg-success opacity-60" />
                )}
                <span
                  className={cn(
                    "relative inline-flex size-2.5 rounded-full",
                    online
                      ? "bg-success"
                      : status === "offline"
                        ? "bg-destructive"
                        : "bg-warning",
                  )}
                />
              </span>
              <span className="text-lg font-semibold tracking-tight">
                {online
                  ? "Agent online"
                  : status === "offline"
                    ? "Agent offline"
                    : "Connecting"}
              </span>
            </div>
            <p className="text-sm text-muted-foreground">
              {online
                ? "The local HTTP control API is reachable."
                : status === "offline"
                  ? "No response from the local control API."
                  : "Probing the local control API."}
            </p>
            <div className="mt-auto flex flex-col gap-1 pt-2">
              <span className="label-eyebrow">Endpoint</span>
              <code className="w-fit max-w-full truncate rounded bg-muted px-1.5 py-0.5 font-mono text-xs text-muted-foreground">
                {typeof window !== "undefined" ? window.location.origin : "—"}
              </code>
            </div>
          </div>

          {/* Identity grid */}
          <div className="grid grid-cols-2 gap-x-6 gap-y-5 sm:grid-cols-3">
            {loading && !health ? (
              Array.from({ length: 6 }).map((_, i) => (
                <div key={i} className="flex flex-col gap-1.5">
                  <Skeleton className="h-3 w-14" />
                  <Skeleton className="h-4 w-20" />
                </div>
              ))
            ) : (
              <>
                <Field label="Firmware" value={health?.version ?? "—"} />
                <Field
                  label="Status"
                  mono={false}
                  value={
                    <span
                      className={cn(
                        "font-mono text-[0.8125rem]",
                        healthy
                          ? "text-success"
                          : health?.status
                            ? "text-warning"
                            : "text-muted-foreground",
                      )}
                    >
                      {health?.status ?? "unknown"}
                    </span>
                  }
                />
                <Field
                  label="Commit"
                  value={<CommitLink commit={health?.commit} short />}
                />
                <Field label="Built" value={fmtBuild(health?.build_time)} />
                <Field
                  label="Instance"
                  value={
                    health?.instance_id ? health.instance_id.slice(0, 12) : "—"
                  }
                />
                <Field
                  label="Bootstrap"
                  mono={false}
                  value={
                    <span className="font-mono text-[0.8125rem]">
                      {runtime?.bs_valid === "1" ? "valid" : "unset"}
                    </span>
                  }
                />
              </>
            )}
          </div>
        </div>
      </Module>

      {/* Runtime readout */}
      <Module label="Runtime">
        <div className="grid grid-cols-2 gap-x-6 gap-y-5 sm:grid-cols-4">
          <Field label="Log level" value={runtime?.log_level ?? "—"} />
          <Field
            label="Heartbeat"
            value={formatDuration(runtime?.heartbeat_interval)}
          />
          <Field
            label="Telemetry"
            value={formatDuration(
              runtime?.telemetry_interval ?? telemetry?.interval,
            )}
          />
          <Field
            label="Term timeout"
            value={formatDuration(runtime?.terminal_session_timeout)}
          />
        </div>
        <div className="mt-5 flex flex-wrap items-center gap-2 border-t border-border pt-4">
          <span className="label-eyebrow mr-1">Telemetry readers</span>
          {readers.map((r) => (
            <span
              key={r.label}
              className={cn(
                "inline-flex items-center gap-1.5 rounded border px-2 py-0.5 font-mono text-xs",
                r.on
                  ? "border-success/30 bg-success/10 text-success"
                  : "border-border bg-muted text-muted-foreground",
              )}
            >
              <span
                className={cn(
                  "size-1.5 rounded-full",
                  r.on ? "bg-success" : "bg-muted-foreground/50",
                )}
              />
              {r.label}
            </span>
          ))}
        </div>
      </Module>

      {/* Console directory */}
      <Module label="Console" bodyClassName="p-0">
        <div className="divide-y divide-border">
          {navGroups.map((group) => {
            const items = group.items.filter((i) => descriptions[i.href]);
            if (items.length === 0) return null;
            return (
              <div key={group.label} className="px-4 py-3">
                <div className="label-eyebrow mb-2">{group.label}</div>
                <ul className="grid gap-1 sm:grid-cols-2">
                  {items.map(({ href, label, icon: Icon }) => (
                    <li key={href}>
                      <a
                        href={href}
                        className="group flex items-center gap-3 rounded-md px-2 py-2 no-underline transition-colors hover:bg-accent/60"
                      >
                        <span className="flex size-8 shrink-0 items-center justify-center rounded-md border bg-muted text-muted-foreground group-hover:border-primary/40 group-hover:text-primary">
                          <Icon className="size-4" />
                        </span>
                        <span className="min-w-0 flex-1">
                          <span className="block text-sm font-medium leading-tight text-foreground">
                            {label}
                          </span>
                          <span className="block truncate text-xs text-muted-foreground">
                            {descriptions[href]}
                          </span>
                        </span>
                        <ChevronRight className="size-4 shrink-0 text-muted-foreground/40 transition-transform group-hover:translate-x-0.5 group-hover:text-primary" />
                      </a>
                    </li>
                  ))}
                </ul>
              </div>
            );
          })}
        </div>
      </Module>
    </div>
  );
}

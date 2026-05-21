// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import {
  Activity,
  ArrowRight,
  Cpu,
  Download,
  MessageSquare,
  Network,
  Settings,
  Terminal,
} from "lucide-react";
import { useEffect, useRef, useState } from "preact/hooks";
import { AgentStatus } from "@/components/agent-status";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { UI_BASE } from "@/routes";

const PREVIEW_LINES = 6;

type Level = "DEBUG" | "INFO" | "WARN" | "ERROR" | "unknown";

function parseLevel(line: string): Level {
  if (line.includes(" DEBUG ")) return "DEBUG";
  if (line.includes(" INFO ")) return "INFO";
  if (line.includes(" WARN ")) return "WARN";
  if (line.includes(" ERROR ")) return "ERROR";
  return "unknown";
}

function levelClass(level: Level): string {
  switch (level) {
    case "DEBUG": return "text-zinc-500";
    case "INFO":  return "text-emerald-400";
    case "WARN":  return "text-yellow-400";
    case "ERROR": return "text-red-400";
    default:      return "text-zinc-300";
  }
}

function AgentLogPreview() {
  const [lines, setLines] = useState<string[]>([]);
  const [connected, setConnected] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const es = new EventSource("/logs");
    es.onopen = () => setConnected(true);
    es.onmessage = (e) => {
      setLines((prev) => [...prev.slice(-(PREVIEW_LINES - 1)), e.data as string]);
    };
    es.onerror = () => setConnected(false);
    return () => es.close();
  }, []);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [lines]);

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <MessageSquare className="h-4 w-4" />
          Agent Log
          <a
            href={`${UI_BASE}/logs`}
            className="ml-auto text-[0.7rem] font-normal text-muted-foreground underline-offset-2 hover:underline"
          >
            View full log →
          </a>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="rounded-lg border bg-zinc-950 p-3 font-mono text-xs leading-relaxed">
          <div className="mb-1.5 flex items-center gap-1.5">
            <span
              className={`h-1.5 w-1.5 rounded-full ${connected ? "bg-emerald-400" : "bg-red-400"}`}
            />
            <span className="text-[0.65rem] text-zinc-500">
              {connected ? "Streaming" : "Connecting…"}
            </span>
          </div>
          {lines.length === 0 ? (
            <p className="text-zinc-600">Waiting for log entries…</p>
          ) : (
            lines.map((line, i) => {
              const level = parseLevel(line);
              return (
                <div key={i} className={`whitespace-pre-wrap break-all ${levelClass(level)}`}>
                  {line}
                </div>
              );
            })
          )}
          <div ref={bottomRef} />
        </div>
      </CardContent>
    </Card>
  );
}

const stats = [
  { label: "Agent Status", value: "Live", sub: "HTTP API reachable" },
  { label: "Services", value: "Local", sub: "Heartbeat registry" },
  { label: "Node-RED", value: "Ready", sub: "Flow management" },
  { label: "Control Plane", value: "MQTT", sub: "Commands and responses" },
];

const features = [
  {
    title: "Configuration",
    description: "Inspect the rendered runtime profile used by this agent.",
    href: `${UI_BASE}/config`,
    icon: Settings,
    foot: "Runtime settings",
  },
  {
    title: "Devices",
    description: "Register, monitor, and manage downstream BLE, serial, and I2C devices.",
    href: `${UI_BASE}/devices`,
    icon: Cpu,
    foot: "Device registry",
  },
  {
    title: "Node-RED",
    description: "Ping Node-RED, read state, fetch flows, and deploy updates.",
    href: `${UI_BASE}/nodered`,
    icon: Network,
    foot: "Flow operations",
  },
  {
    title: "Services",
    description: "View local service heartbeat data reported to the agent.",
    href: `${UI_BASE}/services`,
    icon: Activity,
    foot: "Local visibility",
  },
  {
    title: "Execute",
    description: "Run command requests through the agent control endpoint.",
    href: `${UI_BASE}/exec`,
    icon: Terminal,
    foot: "Remote operations",
  },
  {
    title: "OTA Update",
    description: "Trigger an over-the-air binary update and track its progress.",
    href: `${UI_BASE}/ota`,
    icon: Download,
    foot: "Remote update",
  },
];

export function HomePage() {
  return (
    <div className="space-y-[22px]">
      <div>
        <h1 className="text-[1.35rem] font-bold leading-tight tracking-tight">
          Overview
        </h1>
        <p className="mt-1 text-[0.825rem] text-muted-foreground">
          Magistrala gateway agent status and local control tools.
        </p>
      </div>

      <AgentStatus />

      <section className="grid gap-3.5 sm:grid-cols-2 lg:grid-cols-4">
        {stats.map((stat) => (
          <div
            key={stat.label}
            className="rounded-xl border bg-card px-[18px] py-[15px] shadow-sm"
          >
            <div className="mb-2 text-[0.65rem] font-bold uppercase tracking-[0.07em] text-muted-foreground">
              {stat.label}
            </div>
            <div className="text-[1.4rem] font-bold leading-none tracking-tight">
              {stat.value}
            </div>
            <div className="mt-1 text-[0.7rem] text-muted-foreground">
              {stat.sub}
            </div>
          </div>
        ))}
      </section>

      <section className="grid gap-3.5 md:grid-cols-2">
        {features.map(({ title, description, href, icon: Icon, foot }) => (
          <a
            key={title}
            href={href}
            className="group rounded-xl border bg-card p-[18px] text-left text-card-foreground no-underline shadow-sm transition hover:-translate-y-px hover:border-primary hover:shadow-md hover:ring-4 hover:ring-accent"
          >
            <span className="mb-3 flex h-[38px] w-[38px] items-center justify-center rounded-lg bg-accent text-primary">
              <Icon className="h-5 w-5" />
            </span>
            <h2 className="mb-1 text-sm font-semibold">{title}</h2>
            <p className="mb-3 text-[0.775rem] leading-relaxed text-muted-foreground">
              {description}
            </p>
            <span className="flex items-center gap-2 border-t pt-2.5 text-[0.72rem] text-muted-foreground">
              {foot}
              <ArrowRight className="ml-auto h-3.5 w-3.5 text-primary transition group-hover:translate-x-0.5" />
            </span>
          </a>
        ))}
      </section>

      <AgentLogPreview />
    </div>
  );
}

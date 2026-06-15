// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import {
  Activity,
  ArrowRight,
  Cpu,
  Download,
  Network,
  Settings,
  Terminal,
} from "lucide-react";
import { AgentStatus } from "@/components/agent-status";
import { PageHeader } from "@/components/page-header";
import { UI_BASE } from "@/routes";

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
    description:
      "Register, monitor, and manage downstream BLE, serial, and I2C devices.",
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
    description:
      "Trigger an over-the-air binary update and track its progress.",
    href: `${UI_BASE}/ota`,
    icon: Download,
    foot: "Remote update",
  },
];

export function HomePage() {
  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Overview"
        subtitle="Magistrala gateway agent status and local control tools."
      />

      <AgentStatus />

      <section className="grid gap-3.5 sm:grid-cols-2 lg:grid-cols-4">
        {stats.map((stat) => (
          <div
            key={stat.label}
            className="rounded-xl border bg-card px-4 py-3.5 shadow-sm"
          >
            <div className="mb-2 text-xs font-bold uppercase tracking-wide text-muted-foreground">
              {stat.label}
            </div>
            <div className="text-2xl font-bold leading-none tracking-tight">
              {stat.value}
            </div>
            <div className="mt-1 text-xs text-muted-foreground">{stat.sub}</div>
          </div>
        ))}
      </section>

      <section className="grid gap-3.5 md:grid-cols-2">
        {features.map(({ title, description, href, icon: Icon, foot }) => (
          <a
            key={title}
            href={href}
            className="group rounded-xl border bg-card p-4 text-left text-card-foreground no-underline shadow-sm transition hover:-translate-y-px hover:border-primary hover:shadow-md hover:ring-4 hover:ring-accent"
          >
            <span className="mb-3 flex size-9 items-center justify-center rounded-lg bg-accent text-primary">
              <Icon className="size-5" />
            </span>
            <h2 className="mb-1 text-sm font-semibold">{title}</h2>
            <p className="mb-3 text-xs leading-relaxed text-muted-foreground">
              {description}
            </p>
            <span className="flex items-center gap-2 border-t pt-2.5 text-xs text-muted-foreground">
              {foot}
              <ArrowRight className="ml-auto size-3.5 text-primary transition group-hover:translate-x-0.5" />
            </span>
          </a>
        ))}
      </section>
    </div>
  );
}

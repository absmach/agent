// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import { AgentStatus } from "@/components/agent-status";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Activity, Network, Settings, Terminal } from "lucide-react";

const sections = [
  {
    href: "/config",
    icon: Settings,
    title: "Configuration",
    description:
      "View and update the agent's runtime settings — MQTT credentials, channel, ports, and log level.",
  },
  {
    href: "/nodered",
    icon: Network,
    title: "Node-RED",
    description:
      "Ping Node-RED, inspect state, upload flow files, and deploy or add flows.",
  },
  {
    href: "/services",
    icon: Activity,
    title: "Services",
    description:
      "List all services registered with the agent and inspect their status.",
  },
  {
    href: "/exec",
    icon: Terminal,
    title: "Execute Command",
    description:
      "Run shell commands on the device through the agent and see live output.",
  },
];

export function HomePage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Home</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Magistrala Agent management overview
        </p>
      </div>

      <AgentStatus />

      <div>
        <h2 className="mb-3 text-sm font-semibold text-muted-foreground uppercase tracking-wide">
          Features
        </h2>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {sections.map(({ href, icon: Icon, title, description }) => (
            <a key={href} href={href} className="group">
              <Card className="h-full transition-shadow hover:shadow-md">
                <CardHeader className="pb-2">
                  <div className="mb-2 flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10 text-primary group-hover:bg-primary group-hover:text-primary-foreground transition-colors">
                    <Icon className="h-5 w-5" />
                  </div>
                  <CardTitle className="text-sm">{title}</CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-xs text-muted-foreground leading-relaxed">
                    {description}
                  </p>
                </CardContent>
              </Card>
            </a>
          ))}
        </div>
      </div>
    </div>
  );
}

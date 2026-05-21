// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import {
  Activity,
  Globe,
  Info,
  Loader2,
  Network,
  Phone,
  RefreshCw,
} from "lucide-react";
import { useEffect, useState } from "preact/hooks";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle } from "@/components/ui/card";

interface ServiceInfo {
  name: string;
  last_seen?: string;
  status: string;
  type: string;
  terminal?: number;
  endpoint?: string;
}


export function ServicesCard() {
  const [services, setServices] = useState<ServiceInfo[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function refresh() {
    setLoading(true);
    setError("");
    try {
      const res = await fetch("/services");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setServices(Array.isArray(data) ? data : []);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { refresh(); }, []);

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <Activity className="h-4 w-4" />
          Registered Services
        </CardTitle>
        <Button variant="ghost" size="sm" onClick={refresh} disabled={loading}>
          {loading ? (
            <Loader2 className="h-3 w-3 animate-spin" />
          ) : (
            <RefreshCw className="h-3 w-3" />
          )}
          Refresh
        </Button>
      </CardHeader>

      {error && (
        <div className="border-b px-[18px] py-3 text-sm text-destructive">
          {error}
        </div>
      )}

      <div>
        {services.length > 0 ? (
          services.map((service) => (
            <ServiceRow
              key={`${service.name}-${service.type}-${service.last_seen ?? ""}`}
              service={service}
            />
          ))
        ) : (
          <div className="px-6 py-11 text-center text-muted-foreground">
            <Activity className="mx-auto mb-2.5 h-9 w-9 opacity-25" />
            <h3 className="mb-1 text-[0.85rem] font-semibold text-foreground">
              No services registered yet
            </h3>
            <p className="text-[0.775rem]">
              Services appear here once the agent connects and registers them.
            </p>
          </div>
        )}
      </div>
    </Card>
  );
}

function ServiceRow({ service }: { service: ServiceInfo }) {
  const status = normalizeStatus(service.status);
  const endpoint = service.endpoint || service.type || "unknown endpoint";
  const Icon = pickIcon(endpoint, service.name);

  return (
    <div className="flex items-center gap-[13px] border-b px-[18px] py-[13px] last:border-b-0">
      <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-accent text-primary">
        <Icon className="h-3.5 w-3.5" />
      </div>
      <div className="min-w-0 flex-1">
        <div className="text-[0.825rem] font-semibold">{service.name}</div>
        <div className="truncate font-mono text-[0.7rem] text-muted-foreground">
          {endpoint}
          {service.last_seen
            ? ` · last seen ${new Date(service.last_seen).toLocaleString()}`
            : ""}
        </div>
      </div>
      <div
        className={`flex shrink-0 items-center gap-1 rounded-full px-2 py-0.5 text-[0.7rem] font-semibold ${status.className}`}
      >
        ● {status.label}
      </div>
      <button
        type="button"
        className="inline-flex items-center gap-1 rounded-lg border px-2.5 py-1 text-[0.75rem] font-semibold text-muted-foreground hover:bg-secondary hover:text-foreground"
        title={`${service.name} details`}
      >
        <Info className="h-3 w-3" />
        Details
      </button>
    </div>
  );
}

function normalizeStatus(status: string) {
  switch (status.toLowerCase()) {
    case "online":
    case "running":
      return {
        label: "Running",
        className: "bg-emerald-50 text-emerald-700 dark:bg-emerald-950",
      };
    case "offline":
    case "stopped":
      return {
        label: "Stopped",
        className: "bg-red-50 text-red-600 dark:bg-red-950",
      };
    default:
      return {
        label: "Unknown",
        className: "bg-amber-50 text-amber-700 dark:bg-amber-950",
      };
  }
}

function pickIcon(endpoint: string, name: string) {
  const normalized = `${name} ${endpoint}`.toLowerCase();
  if (normalized.includes("amqp")) {
    return Phone;
  }
  if (normalized.includes("node")) {
    return Network;
  }
  if (normalized.includes("http")) {
    return Globe;
  }
  return Activity;
}

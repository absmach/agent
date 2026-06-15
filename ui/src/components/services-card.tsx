// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import {
  Activity,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  Globe,
  Loader2,
  Network,
  Phone,
  Plus,
  RefreshCw,
  Trash2,
} from "lucide-react";
import { useEffect, useState } from "preact/hooks";
import { EmptyState } from "@/components/empty-state";
import { ErrorAlert } from "@/components/error-alert";
import { StatusBadge, type StatusValue } from "@/components/status-badge";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { UI_BASE } from "@/routes";

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
  const [showAdd, setShowAdd] = useState(false);
  const [name, setName] = useState("");
  const [type, setType] = useState("");
  const [submitting, setSubmitting] = useState(false);

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

  async function addService(e: Event) {
    e.preventDefault();
    if (!name.trim()) return;
    setSubmitting(true);
    setError("");
    try {
      const res = await fetch("/services", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: name.trim(),
          type: type.trim() || "service",
        }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setName("");
      setType("");
      setShowAdd(false);
      await refresh();
    } catch (err) {
      setError(String(err));
    } finally {
      setSubmitting(false);
    }
  }

  async function removeService(svcName: string) {
    try {
      const res = await fetch(`/services/${encodeURIComponent(svcName)}`, {
        method: "DELETE",
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      await refresh();
    } catch (err) {
      setError(String(err));
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <Activity className="size-4" />
          Registered Services
        </CardTitle>
        <div className="ml-auto flex items-center gap-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={refresh}
            disabled={loading}
          >
            {loading ? (
              <Loader2 className="size-3 animate-spin" />
            ) : (
              <RefreshCw className="size-3" />
            )}
            Refresh
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => setShowAdd((s) => !s)}
          >
            <Plus className="size-3" />
            Add Service
          </Button>
        </div>
      </CardHeader>

      {error && (
        <div className="border-b px-4 py-3">
          <ErrorAlert error={error} />
        </div>
      )}

      {showAdd && (
        <form
          onSubmit={addService}
          className="flex flex-wrap items-end gap-3 border-b bg-muted/30 px-4 py-3"
        >
          <div className="flex flex-col gap-1">
            <Label htmlFor="svc-name">Name</Label>
            <Input
              id="svc-name"
              value={name}
              onInput={(e) => setName((e.target as HTMLInputElement).value)}
              placeholder="my-service"
              className="w-48"
            />
          </div>
          <div className="flex flex-col gap-1">
            <Label htmlFor="svc-type">Type</Label>
            <Input
              id="svc-type"
              value={type}
              onInput={(e) => setType((e.target as HTMLInputElement).value)}
              placeholder="service"
              className="w-48"
            />
          </div>
          <Button type="submit" size="sm" disabled={submitting || !name.trim()}>
            {submitting ? (
              <Loader2 className="size-3 animate-spin" />
            ) : (
              <Plus className="size-3" />
            )}
            Register
          </Button>
        </form>
      )}

      <div>
        {services.length > 0 ? (
          services.map((service) => (
            <ServiceRow
              key={`${service.name}-${service.type}-${service.last_seen ?? ""}`}
              service={service}
              onRemove={() => removeService(service.name)}
            />
          ))
        ) : (
          <EmptyState
            icon={<Activity className="size-9" />}
            title="No services registered yet"
            description="Services appear here once the agent connects and registers them."
          />
        )}
      </div>
    </Card>
  );
}

function serviceUIPath(type: string): string | null {
  switch (type.toLowerCase()) {
    case "nodered":
      return `${UI_BASE}/nodered`;
    default:
      return null;
  }
}

function normalizeStatus(status: string): {
  label: string;
  state: StatusValue;
} {
  switch (status.toLowerCase()) {
    case "online":
    case "running":
      return { label: "Running", state: "running" };
    case "offline":
    case "stopped":
      return { label: "Stopped", state: "stopped" };
    default:
      return { label: "Unknown", state: "unknown" };
  }
}

function pickIcon(endpoint: string, name: string) {
  const normalized = `${name} ${endpoint}`.toLowerCase();
  if (normalized.includes("amqp")) return Phone;
  if (normalized.includes("node")) return Network;
  if (normalized.includes("http")) return Globe;
  return Activity;
}

function ServiceRow({
  service,
  onRemove,
}: {
  service: ServiceInfo;
  onRemove: () => void;
}) {
  const [open, setOpen] = useState(false);
  const status = normalizeStatus(service.status);
  const endpoint = service.endpoint || service.type || "unknown endpoint";
  const Icon = pickIcon(endpoint, service.name);
  const uiPath = serviceUIPath(service.type);

  return (
    <div className="border-b last:border-b-0">
      <div className="flex items-center gap-3 px-4 py-3">
        <div className="flex size-8 shrink-0 items-center justify-center rounded-md bg-accent text-primary">
          <Icon className="size-3.5" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="text-sm font-semibold">{service.name}</div>
          <div className="truncate font-mono text-xs text-muted-foreground">
            {endpoint}
            {service.last_seen
              ? ` · last seen ${new Date(service.last_seen).toLocaleString()}`
              : ""}
          </div>
        </div>
        <StatusBadge status={status.state} label={status.label} />
        {uiPath && (
          <a
            href={uiPath}
            className="inline-flex items-center gap-1 rounded-lg border px-2.5 py-1 text-xs font-semibold text-muted-foreground transition-colors hover:bg-secondary hover:text-foreground"
          >
            <ExternalLink className="size-3" />
            Open UI
          </a>
        )}
        <button
          type="button"
          onClick={() => setOpen((o) => !o)}
          className="inline-flex items-center gap-1 rounded-lg border px-2.5 py-1 text-xs font-semibold text-muted-foreground transition-colors hover:bg-secondary hover:text-foreground"
        >
          {open ? (
            <ChevronUp className="size-3" />
          ) : (
            <ChevronDown className="size-3" />
          )}
          Details
        </button>
        <button
          type="button"
          onClick={onRemove}
          title="Remove service"
          className="inline-flex items-center gap-1 rounded-lg border px-2.5 py-1 text-xs font-semibold text-muted-foreground transition-colors hover:bg-destructive/10 hover:text-destructive"
        >
          <Trash2 className="size-3" />
        </button>
      </div>

      {open && (
        <div className="grid grid-cols-2 gap-x-8 gap-y-2 border-t bg-muted/30 px-4 py-3 sm:grid-cols-4">
          <DetailField label="Name" value={service.name} />
          <DetailField label="Type" value={service.type} />
          <DetailField label="Status" value={service.status} />
          <DetailField
            label="Last seen"
            value={
              service.last_seen
                ? new Date(service.last_seen).toLocaleString()
                : "—"
            }
          />
          {service.terminal !== undefined && service.terminal > 0 && (
            <DetailField
              label="Terminal sessions"
              value={String(service.terminal)}
            />
          )}
        </div>
      )}
    </div>
  );
}

function DetailField({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
        {label}
      </div>
      <div className="mt-0.5 font-mono text-xs">{value}</div>
    </div>
  );
}

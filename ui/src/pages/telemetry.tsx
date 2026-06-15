// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import {
  Activity,
  CheckCircle2,
  Clock,
  Cpu,
  Disc,
  HardDrive,
  Loader2,
  MemoryStick,
  RefreshCw,
  Thermometer,
  Wifi,
} from "lucide-react";
import { useEffect, useState } from "preact/hooks";
import { EmptyState } from "@/components/empty-state";
import { ErrorAlert } from "@/components/error-alert";
import { PageHeader } from "@/components/page-header";
import { StatusBadge } from "@/components/status-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { formatBytes, formatDuration } from "@/lib/utils";

interface TelemetryInfo {
  interval: string;
  include_temperature: boolean;
  include_network: boolean;
  include_load: boolean;
}

interface TelemetryData {
  uptime?: number;
  mem_total?: number;
  mem_available?: number;
  mem_used?: number;
  cpu_temperature?: number;
  rssi?: number;
  load_avg_1m?: number;
  load_avg_5m?: number;
  load_avg_15m?: number;
  disk_usage_percent?: number;
  devices_active?: number;
}

export function TelemetryPage() {
  const [telemetry, setTelemetry] = useState<TelemetryInfo | null>(null);
  const [data, setData] = useState<TelemetryData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function fetchAll() {
    setLoading(true);
    setError("");
    try {
      const [cfgRes, dataRes] = await Promise.allSettled([
        fetch("/config", { cache: "no-store" }).then((r) => r.json()),
        fetch("/telemetry/data", { cache: "no-store" }).then((r) => r.json()),
      ]);
      if (cfgRes.status === "fulfilled") {
        const t = cfgRes.value.telemetry || {};
        setTelemetry({
          interval: t.interval || "0s",
          include_temperature: t.include_temperature !== false,
          include_network: t.include_network !== false,
          include_load: t.include_load !== false,
        });
      }
      if (dataRes.status === "fulfilled") {
        setData(dataRes.value);
      }
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchAll();
    const id = setInterval(() => {
      fetch("/telemetry/data", { cache: "no-store" })
        .then((r) => r.json())
        .then(setData)
        .catch(() => {});
    }, 5000);
    return () => clearInterval(id);
  }, []);

  const enabled = telemetry?.interval && telemetry.interval !== "0s";

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Telemetry"
        subtitle="Periodic gateway telemetry configuration and reader status."
        actions={
          <Button
            variant="ghost"
            size="sm"
            onClick={fetchAll}
            disabled={loading}
          >
            {loading ? (
              <Loader2 className="size-3 animate-spin" />
            ) : (
              <RefreshCw className="size-3" />
            )}
            Refresh
          </Button>
        }
      />

      <ErrorAlert error={error} />

      <Card>
        <CardHeader>
          <CardTitle>
            <Activity className="size-4" />
            Telemetry Status
            <StatusBadge
              status={enabled ? "enabled" : "disabled"}
              label={enabled ? "Enabled" : "Disabled"}
              className="ml-auto"
            />
          </CardTitle>
        </CardHeader>
        <CardContent>
          {telemetry ? (
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="flex items-center gap-3 rounded-lg border px-4 py-3">
                <Clock className="size-5 text-muted-foreground" />
                <div>
                  <div className="text-xs font-medium text-muted-foreground">
                    Publish Interval
                  </div>
                  <div className="font-mono text-sm font-semibold">
                    {formatDuration(telemetry.interval)}
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-3 rounded-lg border px-4 py-3">
                <Cpu className="size-5 text-muted-foreground" />
                <div>
                  <div className="text-xs font-medium text-muted-foreground">
                    CPU Temperature
                  </div>
                  <div className="text-sm font-semibold">
                    {telemetry.include_temperature ? "Enabled" : "Disabled"}
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-3 rounded-lg border px-4 py-3">
                <Wifi className="size-5 text-muted-foreground" />
                <div>
                  <div className="text-xs font-medium text-muted-foreground">
                    Network RSSI
                  </div>
                  <div className="text-sm font-semibold">
                    {telemetry.include_network ? "Enabled" : "Disabled"}
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-3 rounded-lg border px-4 py-3">
                <Disc className="size-5 text-muted-foreground" />
                <div>
                  <div className="text-xs font-medium text-muted-foreground">
                    Load Average
                  </div>
                  <div className="text-sm font-semibold">
                    {telemetry.include_load ? "Enabled" : "Disabled"}
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <EmptyState
              icon={<Activity className="size-8" />}
              title="No telemetry data"
              description="Telemetry config not available."
            />
          )}
        </CardContent>
      </Card>

      {data && (
        <Card>
          <CardHeader>
            <CardTitle>
              <Activity className="size-4" />
              Current Readings
              <span className="ml-auto text-xs font-normal text-muted-foreground">
                updates every 5s
              </span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              <Reading
                icon={<Clock className="size-4" />}
                label="Uptime"
                value={formatDuration(data.uptime ? data.uptime * 1e9 : null)}
              />
              <Reading
                icon={<MemoryStick className="size-4" />}
                label="Memory"
                value={
                  data.mem_used != null && data.mem_total != null
                    ? `${formatBytes(data.mem_used)} / ${formatBytes(data.mem_total)}`
                    : "—"
                }
                sub={
                  data.mem_used != null && data.mem_total != null
                    ? `${((data.mem_used / data.mem_total) * 100).toFixed(0)}% used`
                    : undefined
                }
              />
              <Reading
                icon={<HardDrive className="size-4" />}
                label="Disk Usage"
                value={
                  data.disk_usage_percent != null
                    ? `${data.disk_usage_percent.toFixed(1)}%`
                    : "—"
                }
              />
              <Reading
                icon={<Thermometer className="size-4" />}
                label="CPU Temp"
                value={
                  data.cpu_temperature != null
                    ? `${data.cpu_temperature.toFixed(1)} \u00B0C`
                    : "—"
                }
              />
              <Reading
                icon={<Wifi className="size-4" />}
                label="RSSI"
                value={data.rssi != null ? `${data.rssi.toFixed(0)} dBm` : "—"}
              />
              <Reading
                icon={<Disc className="size-4" />}
                label="Load Avg"
                value={
                  data.load_avg_1m != null
                    ? `${data.load_avg_1m.toFixed(2)} / ${data.load_avg_5m?.toFixed(2) ?? "—"} / ${data.load_avg_15m?.toFixed(2) ?? "—"}`
                    : "—"
                }
                sub="1m / 5m / 15m"
              />
            </div>
          </CardContent>
        </Card>
      )}

      {enabled && (
        <Card>
          <CardHeader>
            <CardTitle>
              <Activity className="size-4" />
              Telemetry Readers
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-col gap-2">
              <ReaderRow
                name="Uptime"
                desc="Go runtime time since start"
                alwaysOn
              />
              <ReaderRow
                name="Memory (heap_free, heap_used)"
                desc="/proc/meminfo"
                alwaysOn
              />
              <ReaderRow
                name="Disk Usage"
                desc="syscall.Statfs('/')"
                alwaysOn
              />
              <ReaderRow
                name="CPU Temperature"
                desc="/sys/class/thermal/thermal_zone*/temp"
                enabled={telemetry.include_temperature}
              />
              <ReaderRow
                name="Network RSSI"
                desc="/proc/net/wireless"
                enabled={telemetry.include_network}
              />
              <ReaderRow
                name="Load Average (1m, 5m, 15m)"
                desc="/proc/loadavg"
                enabled={telemetry.include_load}
              />
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function Reading({
  icon,
  label,
  value,
  sub,
}: {
  icon: preact.ComponentChildren;
  label: string;
  value: string;
  sub?: string;
}) {
  return (
    <div className="flex items-center gap-3 rounded-lg border px-4 py-3">
      <span className="flex size-8 shrink-0 items-center justify-center rounded-md bg-muted text-muted-foreground">
        {icon}
      </span>
      <div className="min-w-0">
        <div className="text-xs font-medium text-muted-foreground">{label}</div>
        <div className="truncate font-mono text-sm font-semibold">{value}</div>
        {sub && <div className="text-xs text-muted-foreground">{sub}</div>}
      </div>
    </div>
  );
}

function ReaderRow({
  name,
  desc,
  alwaysOn,
  enabled,
}: {
  name: string;
  desc: string;
  alwaysOn?: boolean;
  enabled?: boolean;
}) {
  const active = alwaysOn || enabled;
  return (
    <div className="flex items-center gap-3 rounded-lg border px-4 py-2.5">
      <CheckCircle2
        className={`size-4 shrink-0 ${active ? "text-success" : "text-muted-foreground/40"}`}
      />
      <div className="min-w-0 flex-1">
        <div className="text-sm font-medium">{name}</div>
        <div className="font-mono text-xs text-muted-foreground">{desc}</div>
      </div>
      <StatusBadge
        status={active ? "active" : "inactive"}
        label={active ? "Active" : "Inactive"}
      />
    </div>
  );
}

// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import {
  Activity,
  CheckCircle2,
  Clock,
  Cpu,
  Disc,
  Loader2,
  RefreshCw,
  Wifi,
} from "lucide-react";
import { useEffect, useState } from "preact/hooks";
import { EmptyState } from "@/components/empty-state";
import { ErrorAlert } from "@/components/error-alert";
import { PageHeader } from "@/components/page-header";
import { StatusBadge } from "@/components/status-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

interface TelemetryInfo {
  interval: string;
  include_temperature: boolean;
  include_network: boolean;
  include_load: boolean;
}

export function TelemetryPage() {
  const [telemetry, setTelemetry] = useState<TelemetryInfo | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function fetchTelemetry() {
    setLoading(true);
    setError("");
    try {
      const res = await fetch("/config");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      const t = data.telemetry || {};
      setTelemetry({
        interval: t.interval || "0s",
        include_temperature: t.include_temperature !== false,
        include_network: t.include_network !== false,
        include_load: t.include_load !== false,
      });
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchTelemetry();
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
            onClick={fetchTelemetry}
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
                    {telemetry.interval}
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

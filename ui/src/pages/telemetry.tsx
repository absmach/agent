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
    <div className="space-y-[22px]">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-[1.35rem] font-bold leading-tight tracking-tight">
            Telemetry
          </h1>
          <p className="mt-1 text-[0.825rem] text-muted-foreground">
            Periodic gateway telemetry configuration and reader status.
          </p>
        </div>
        <Button
          variant="ghost"
          size="sm"
          onClick={fetchTelemetry}
          disabled={loading}
        >
          {loading ? (
            <Loader2 className="h-3 w-3 animate-spin" />
          ) : (
            <RefreshCw className="h-3 w-3" />
          )}
          Refresh
        </Button>
      </div>

      {error && (
        <div className="rounded-lg border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">
          {error}
        </div>
      )}

      <Card>
        <CardHeader>
          <CardTitle>
            <Activity className="h-4 w-4" />
            Telemetry Status
            <span
              className={`ml-auto flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[0.7rem] font-semibold ${
                enabled
                  ? "bg-emerald-50 text-emerald-700 dark:bg-emerald-950"
                  : "bg-zinc-100 text-zinc-500 dark:bg-zinc-800"
              }`}
            >
              <span className="h-1.5 w-1.5 rounded-full bg-current" />
              {enabled ? "Enabled" : "Disabled"}
            </span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          {telemetry ? (
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="flex items-center gap-3 rounded-lg border px-4 py-3">
                <Clock className="h-5 w-5 text-muted-foreground" />
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
                <Cpu className="h-5 w-5 text-muted-foreground" />
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
                <Wifi className="h-5 w-5 text-muted-foreground" />
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
                <Disc className="h-5 w-5 text-muted-foreground" />
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
            <div className="py-8 text-center text-muted-foreground">
              <Activity className="mx-auto mb-2 h-8 w-8 opacity-25" />
              <p className="text-[0.775rem]">Telemetry config not available.</p>
            </div>
          )}
        </CardContent>
      </Card>

      {enabled && (
        <Card>
          <CardHeader>
            <CardTitle>
              <Activity className="h-4 w-4" />
              Telemetry Readers
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
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
        className={`h-4 w-4 shrink-0 ${active ? "text-emerald-500" : "text-zinc-300"}`}
      />
      <div className="min-w-0 flex-1">
        <div className="text-sm font-medium">{name}</div>
        <div className="font-mono text-[0.7rem] text-muted-foreground">
          {desc}
        </div>
      </div>
      <span
        className={`text-[0.65rem] font-semibold ${active ? "text-emerald-500" : "text-zinc-400"}`}
      >
        {active ? "● Active" : "○ Inactive"}
      </span>
    </div>
  );
}

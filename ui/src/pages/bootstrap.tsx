import { Loader2, RefreshCw, Server } from "lucide-react";
import { useEffect, useState } from "preact/hooks";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

interface BootstrapInfo {
  active: boolean;
  external_id: string;
  external_key: string;
  domain_id: string;
  mqtt_url: string;
  mqtt_username: string;
  ctrl_channel_id: string;
  data_channel_id: string;
  cache_path: string;
  cache_valid: boolean;
}

export function BootstrapPage() {
  const [info, setInfo] = useState<BootstrapInfo | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function fetchBootstrap() {
    setLoading(true);
    setError("");
    try {
      const res = await fetch("/config");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();

      const hasBootstrap = !!(
        data.provision?.clients_url || data.bootstrap_url
      );
      setInfo({
        active: hasBootstrap || !!data.domain_id,
        external_id: data.bootstrap_external_id || "—",
        external_key: data.bootstrap_external_key || "—",
        domain_id: data.domain_id || "—",
        mqtt_url: data.mqtt?.url || "—",
        mqtt_username: data.mqtt?.username || "—",
        ctrl_channel_id: data.channels?.ctrl_id || "—",
        data_channel_id: data.channels?.data_id || "—",
        cache_path: data.bootstrap_cache_path || "—",
        cache_valid: data.bs_valid !== "0",
      });
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchBootstrap();
  }, []);

  return (
    <div className="space-y-[22px]">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-[1.35rem] font-bold leading-tight tracking-tight">
            Bootstrap
          </h1>
          <p className="mt-1 text-[0.825rem] text-muted-foreground">
            Profile-based provisioning status and configuration.
          </p>
        </div>
        <Button
          variant="ghost"
          size="sm"
          onClick={fetchBootstrap}
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
            <Server className="h-4 w-4" />
            Bootstrap Status
            {info && (
              <span
                className={`ml-auto flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[0.7rem] font-semibold ${
                  info.active
                    ? "bg-emerald-50 text-emerald-700 dark:bg-emerald-950"
                    : "bg-amber-50 text-amber-700 dark:bg-amber-950"
                }`}
              >
                <span className="h-1.5 w-1.5 rounded-full bg-current" />
                {info.active ? "Active" : "Not Configured"}
              </span>
            )}
          </CardTitle>
        </CardHeader>
        <CardContent>
          {info ? (
            <div className="grid gap-x-8 gap-y-3 sm:grid-cols-2">
              <DetailField
                label="Provisioning"
                value={info.active ? "Enabled" : "Disabled"}
              />
              <DetailField label="Domain ID" value={info.domain_id} />
              <DetailField label="External ID" value={info.external_id} />
              <DetailField label="MQTT URL" value={info.mqtt_url} />
              <DetailField label="MQTT Username" value={info.mqtt_username} />
              <DetailField
                label="Control Channel"
                value={info.ctrl_channel_id}
              />
              <DetailField label="Data Channel" value={info.data_channel_id} />
              <DetailField
                label="Cache Status"
                value={info.cache_valid ? "Valid" : "Invalidated"}
              />
            </div>
          ) : (
            <div className="py-8 text-center text-muted-foreground">
              <Server className="mx-auto mb-2 h-8 w-8 opacity-25" />
              <p className="text-[0.775rem]">Bootstrap info not available.</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function DetailField({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-[0.65rem] font-semibold uppercase tracking-wide text-muted-foreground">
        {label}
      </div>
      <div className="mt-0.5 break-all font-mono text-[0.8rem]">{value}</div>
    </div>
  );
}

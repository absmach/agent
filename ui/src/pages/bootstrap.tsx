// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import { Loader2, RefreshCw, Server } from "lucide-react";
import { useEffect, useState } from "preact/hooks";
import { EmptyState } from "@/components/empty-state";
import { ErrorAlert } from "@/components/error-alert";
import { PageHeader } from "@/components/page-header";
import { StatusBadge } from "@/components/status-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

interface BootstrapInfo {
  active: boolean;
  external_id: string;
  external_key: string;
  tenant_id: string;
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

      const hasBootstrap = !!(data.provision?.atom_url || data.bootstrap_url);
      setInfo({
        active: hasBootstrap || !!data.tenant_id,
        external_id: data.bootstrap_external_id || "—",
        external_key: data.bootstrap_external_key || "—",
        tenant_id: data.tenant_id || "—",
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
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Bootstrap"
        subtitle="Profile-based provisioning status and configuration."
        actions={
          <Button
            variant="ghost"
            size="sm"
            onClick={fetchBootstrap}
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
            <Server className="size-4" />
            Bootstrap Status
            {info && (
              <StatusBadge
                status={info.active ? "active" : "pending"}
                label={info.active ? "Active" : "Not Configured"}
                className="ml-auto"
              />
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
              <DetailField label="Tenant ID" value={info.tenant_id} />
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
            <EmptyState
              icon={<Server className="size-8" />}
              title="No bootstrap data"
              description="Bootstrap info not available."
            />
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function DetailField({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
        {label}
      </div>
      <div className="mt-0.5 break-all font-mono text-sm">{value}</div>
    </div>
  );
}

// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import {
  AlertCircle,
  CheckCircle2,
  Heart,
  Loader2,
  RefreshCw,
} from "lucide-react";
import { useEffect, useState } from "preact/hooks";
import { CommitLink } from "@/components/commit-link";
import { EmptyState } from "@/components/empty-state";
import { ErrorAlert } from "@/components/error-alert";
import { PageHeader } from "@/components/page-header";
import { StatusBadge } from "@/components/status-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

interface HealthInfo {
  status: string;
  version: string;
  commit: string;
  description: string;
  build_time: string;
  instance_id: string;
}

export function HealthPage() {
  const [health, setHealth] = useState<HealthInfo | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function fetchHealth() {
    setLoading(true);
    setError("");
    try {
      const res = await fetch("/health");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setHealth(await res.json());
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchHealth();
  }, []);

  const isPass = health?.status === "pass";

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Health"
        subtitle="Agent health status and version information."
        actions={
          <Button
            variant="ghost"
            size="sm"
            onClick={fetchHealth}
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

      {health && (
        <>
          <Card>
            <CardHeader>
              <CardTitle>
                <Heart className="size-4" />
                Status
                <StatusBadge
                  status={isPass ? "pass" : "fail"}
                  label={health.status}
                  className="ml-auto"
                />
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 gap-x-8 gap-y-3 sm:grid-cols-3">
                <DetailField label="Status" value={health.status} />
                <DetailField label="Version" value={health.version} />
                <DetailField
                  label="Commit"
                  value={<CommitLink commit={health.commit} />}
                />
                <DetailField label="Service" value={health.description} />
                <DetailField label="Build Time" value={health.build_time} />
                <DetailField
                  label="Instance ID"
                  value={health.instance_id || "—"}
                />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>
                <AlertCircle className="size-4" />
                Checkers
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex flex-col gap-3">
                <div className="flex items-center gap-3 rounded-lg border px-4 py-3">
                  <div
                    className={`flex size-6 items-center justify-center rounded-full ${isPass ? "bg-success/15 text-success" : "bg-destructive/15 text-destructive"}`}
                  >
                    {isPass ? (
                      <CheckCircle2 className="size-3.5" />
                    ) : (
                      <AlertCircle className="size-3.5" />
                    )}
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="text-sm font-medium">MQTT Connection</div>
                    <div className="text-xs text-muted-foreground">
                      {isPass
                        ? "Broker is reachable"
                        : "Broker is not reachable"}
                    </div>
                  </div>
                  <StatusBadge
                    status={isPass ? "pass" : "fail"}
                    label={isPass ? "Healthy" : "Unhealthy"}
                  />
                </div>
              </div>
            </CardContent>
          </Card>
        </>
      )}

      {!health && !loading && !error && (
        <Card>
          <CardContent>
            <EmptyState
              icon={<Heart className="size-9" />}
              title="No health data"
              description="Click refresh to load health data."
            />
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function DetailField({
  label,
  value,
}: {
  label: string;
  value: preact.ComponentChildren;
}) {
  return (
    <div>
      <div className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
        {label}
      </div>
      <div className="mt-0.5 font-mono text-sm">{value}</div>
    </div>
  );
}

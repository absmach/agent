import {
  AlertCircle,
  CheckCircle2,
  Heart,
  Loader2,
  RefreshCw,
} from "lucide-react";
import { useEffect, useState } from "preact/hooks";
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
    <div className="space-y-[22px]">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-[1.35rem] font-bold leading-tight tracking-tight">
            Health
          </h1>
          <p className="mt-1 text-[0.825rem] text-muted-foreground">
            Agent health status and version information.
          </p>
        </div>
        <Button
          variant="ghost"
          size="sm"
          onClick={fetchHealth}
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

      {health && (
        <>
          <Card>
            <CardHeader>
              <CardTitle>
                <Heart className="h-4 w-4" />
                Status
                <span
                  className={`ml-auto flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[0.7rem] font-semibold ${
                    isPass
                      ? "bg-emerald-50 text-emerald-700 dark:bg-emerald-950"
                      : "bg-red-50 text-red-600 dark:bg-red-950"
                  }`}
                >
                  {isPass ? (
                    <CheckCircle2 className="h-3 w-3" />
                  ) : (
                    <AlertCircle className="h-3 w-3" />
                  )}
                  {health.status}
                </span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 gap-x-8 gap-y-3 sm:grid-cols-3">
                <DetailField label="Status" value={health.status} />
                <DetailField label="Version" value={health.version} />
                <DetailField label="Commit" value={health.commit} />
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
                <AlertCircle className="h-4 w-4" />
                Checkers
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                <div className="flex items-center gap-3 rounded-lg border px-4 py-3">
                  <div
                    className={`flex h-6 w-6 items-center justify-center rounded-full ${isPass ? "bg-emerald-100 text-emerald-600 dark:bg-emerald-900" : "bg-red-100 text-red-600 dark:bg-red-900"}`}
                  >
                    {isPass ? (
                      <CheckCircle2 className="h-3.5 w-3.5" />
                    ) : (
                      <AlertCircle className="h-3.5 w-3.5" />
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
                  <span
                    className={`text-[0.7rem] font-semibold ${isPass ? "text-emerald-500" : "text-red-500"}`}
                  >
                    ● {isPass ? "Healthy" : "Unhealthy"}
                  </span>
                </div>
              </div>
            </CardContent>
          </Card>
        </>
      )}

      {!health && !loading && !error && (
        <Card>
          <CardContent>
            <div className="py-11 text-center text-muted-foreground">
              <Heart className="mx-auto mb-2.5 h-9 w-9 opacity-25" />
              <p className="text-[0.775rem]">
                Click refresh to load health data.
              </p>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function DetailField({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-[0.65rem] font-semibold uppercase tracking-wide text-muted-foreground">
        {label}
      </div>
      <div className="mt-0.5 font-mono text-[0.8rem]">{value}</div>
    </div>
  );
}

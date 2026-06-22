// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import {
  AlertCircle,
  CheckCircle2,
  Copy,
  Eye,
  EyeOff,
  Loader2,
  Power,
  RefreshCw,
  Save,
} from "lucide-react";
import { useCallback, useEffect, useState } from "preact/hooks";
import { ConfigCard } from "@/components/config-card";
import { EmptyState } from "@/components/empty-state";
import { ErrorAlert } from "@/components/error-alert";
import { PageHeader } from "@/components/page-header";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select } from "@/components/ui/select";
import { useToast } from "@/components/ui/toaster";

interface RuntimeConfig {
  log_level: string;
  heartbeat_interval: string;
  telemetry_interval: string;
  terminal_session_timeout: string;
  command_secret: string;
  bs_valid: string;
}

const RUNTIME_KEYS: {
  key: keyof RuntimeConfig;
  label: string;
  type: string;
  options?: string[];
}[] = [
  {
    key: "log_level",
    label: "Log Level",
    type: "select",
    options: ["debug", "info", "warn", "error"],
  },
  { key: "heartbeat_interval", label: "Heartbeat Interval", type: "text" },
  { key: "telemetry_interval", label: "Telemetry Interval", type: "text" },
  {
    key: "terminal_session_timeout",
    label: "Terminal Session Timeout",
    type: "text",
  },
  { key: "command_secret", label: "Command Secret", type: "password" },
  {
    key: "bs_valid",
    label: "Bootstrap Valid",
    type: "select",
    options: ["0", "1"],
  },
];

export function ConfigPage() {
  const { toast } = useToast();
  const [runtimeConfig, setRuntimeConfig] = useState<RuntimeConfig | null>(
    null,
  );
  const [runtimeLoading, setRuntimeLoading] = useState(false);
  const [runtimeError, setRuntimeError] = useState("");
  const [editValues, setEditValues] = useState<Record<string, string>>({});
  const [savingKey, setSavingKey] = useState<string | null>(null);
  const [saveStatus, setSaveStatus] = useState<{
    key: string;
    ok: boolean;
    msg: string;
  } | null>(null);

  const fetchRuntimeConfig = useCallback(async () => {
    setRuntimeLoading(true);
    setRuntimeError("");
    try {
      const res = await fetch("/config/runtime");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      const cfg: RuntimeConfig = data.config;
      setRuntimeConfig(cfg);
      const vals: Record<string, string> = {};
      for (const k of RUNTIME_KEYS) {
        vals[k.key] = cfg[k.key] || "";
      }
      setEditValues(vals);
    } catch (e) {
      setRuntimeError(String(e));
    } finally {
      setRuntimeLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchRuntimeConfig();
  }, [fetchRuntimeConfig]);

  async function saveRuntimeKey(key: string) {
    setSavingKey(key);
    setSaveStatus(null);
    try {
      const res = await fetch("/config/runtime", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ key, value: editValues[key] }),
      });
      if (!res.ok) {
        const txt = await res.text();
        throw new Error(txt || `HTTP ${res.status}`);
      }
      setSaveStatus({ key, ok: true, msg: "Saved" });
      setTimeout(() => setSaveStatus(null), 2000);
    } catch (e) {
      setSaveStatus({ key, ok: false, msg: String(e) });
    } finally {
      setSavingKey(null);
    }
  }

  const [resetModal, setResetModal] = useState(false);
  const [resetMode, setResetMode] = useState("graceful");
  const [resetting, setResetting] = useState(false);
  const [resetError, setResetError] = useState("");
  const [secretVisible, setSecretVisible] = useState(false);

  async function doReset() {
    setResetting(true);
    setResetError("");
    try {
      const res = await fetch("/reset", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode: resetMode }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
    } catch (e) {
      setResetError(String(e));
    } finally {
      setResetting(false);
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Configuration"
        subtitle="View and update the agent runtime settings."
      />

      <ConfigCard />

      <Card>
        <CardHeader>
          <CardTitle>
            <RefreshCw className="size-4" />
            Runtime Configuration
          </CardTitle>
          <Button
            variant="ghost"
            size="sm"
            onClick={fetchRuntimeConfig}
            disabled={runtimeLoading}
          >
            {runtimeLoading ? (
              <Loader2 className="size-3 animate-spin" />
            ) : (
              <RefreshCw className="size-3" />
            )}
            Refresh
          </Button>
        </CardHeader>
        <CardContent>
          {runtimeError && <ErrorAlert error={runtimeError} className="mb-4" />}
          {runtimeConfig ? (
            <div className="grid gap-4 sm:grid-cols-2">
              {RUNTIME_KEYS.map(({ key, label, type, options }) => (
                <div key={key} className="flex flex-col gap-1.5">
                  <Label htmlFor={`rt-${key}`}>{label}</Label>
                  <div className="flex gap-2">
                    {type === "select" && options ? (
                      <Select
                        id={`rt-${key}`}
                        value={editValues[key] || ""}
                        onChange={(e) =>
                          setEditValues((v) => ({
                            ...v,
                            [key]: (e.target as HTMLSelectElement).value,
                          }))
                        }
                      >
                        {options.map((o) => (
                          <option key={o} value={o}>
                            {o}
                          </option>
                        ))}
                      </Select>
                    ) : type === "password" ? (
                      <div className="relative flex-1">
                        <Input
                          id={`rt-${key}`}
                          type={secretVisible ? "text" : "password"}
                          value={editValues[key] || ""}
                          onInput={(e) =>
                            setEditValues((v) => ({
                              ...v,
                              [key]: (e.target as HTMLInputElement).value,
                            }))
                          }
                          className="pr-14"
                        />
                        <div className="absolute right-1 top-1/2 flex -translate-y-1/2 items-center gap-0.5">
                          <button
                            type="button"
                            onClick={() => setSecretVisible((v) => !v)}
                            className="rounded p-1.5 text-muted-foreground transition-colors hover:text-foreground"
                            title={secretVisible ? "Hide" : "Show"}
                          >
                            {secretVisible ? (
                              <EyeOff className="size-3.5" />
                            ) : (
                              <Eye className="size-3.5" />
                            )}
                          </button>
                          <button
                            type="button"
                            onClick={async () => {
                              await navigator.clipboard.writeText(
                                editValues[key] || "",
                              );
                              toast({
                                message: "Copied to clipboard",
                                variant: "success",
                              });
                            }}
                            className="rounded p-1.5 text-muted-foreground transition-colors hover:text-foreground"
                            title="Copy to clipboard"
                          >
                            <Copy className="size-3.5" />
                          </button>
                        </div>
                      </div>
                    ) : (
                      <Input
                        id={`rt-${key}`}
                        type={type}
                        value={editValues[key] || ""}
                        onInput={(e) =>
                          setEditValues((v) => ({
                            ...v,
                            [key]: (e.target as HTMLInputElement).value,
                          }))
                        }
                      />
                    )}
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => saveRuntimeKey(key)}
                      disabled={savingKey === key}
                      className="shrink-0"
                    >
                      {savingKey === key ? (
                        <Loader2 className="size-3 animate-spin" />
                      ) : (
                        <Save className="size-3" />
                      )}
                    </Button>
                  </div>
                  {saveStatus?.key === key && (
                    <div
                      className={`flex items-center gap-1.5 text-xs ${saveStatus.ok ? "text-success" : "text-destructive"}`}
                    >
                      {saveStatus.ok ? (
                        <CheckCircle2 className="size-3" />
                      ) : (
                        <AlertCircle className="size-3" />
                      )}
                      {saveStatus.msg}
                    </div>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <EmptyState
              icon={<RefreshCw className="size-8" />}
              title="No runtime config"
              description="Click refresh to load runtime config."
            />
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>
            <Power className="size-4" />
            Reset Agent
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="mb-3 text-sm text-muted-foreground">
            Restart the agent process. This will disconnect all services
            momentarily.
          </p>
          {!resetModal ? (
            <Button
              variant="destructive"
              size="sm"
              onClick={() => setResetModal(true)}
            >
              <Power className="size-3" />
              Reset Agent
            </Button>
          ) : (
            <div className="flex flex-col gap-3 rounded-lg border border-destructive/30 bg-destructive/5 px-4 py-3">
              <p className="text-sm font-medium text-destructive">
                Are you sure you want to reset the agent?
              </p>
              <div className="flex items-center gap-2">
                <Label htmlFor="reset-mode">Mode:</Label>
                <Select
                  id="reset-mode"
                  value={resetMode}
                  onChange={(e) =>
                    setResetMode((e.target as HTMLSelectElement).value)
                  }
                >
                  <option value="graceful">Graceful</option>
                  <option value="immediate">Immediate</option>
                  <option value="watchdog">Watchdog</option>
                </Select>
              </div>
              {resetError && (
                <p className="text-sm text-destructive">{resetError}</p>
              )}
              <div className="flex gap-2">
                <Button
                  variant="destructive"
                  size="sm"
                  onClick={doReset}
                  disabled={resetting}
                >
                  {resetting ? (
                    <Loader2 className="size-3 animate-spin" />
                  ) : (
                    <Power className="size-3" />
                  )}
                  {resetting ? "Resetting…" : "Confirm Reset"}
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setResetModal(false)}
                >
                  Cancel
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

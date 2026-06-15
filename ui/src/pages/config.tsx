// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import {
  AlertCircle,
  CheckCircle2,
  Loader2,
  Power,
  RefreshCw,
  Save,
} from "lucide-react";
import { useCallback, useEffect, useState } from "preact/hooks";
import { ConfigCard } from "@/components/config-card";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select } from "@/components/ui/select";

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
    <div className="space-y-[22px]">
      <div>
        <h1 className="text-[1.35rem] font-bold leading-tight tracking-tight">
          Configuration
        </h1>
        <p className="mt-1 text-[0.825rem] text-muted-foreground">
          View and update the agent runtime settings.
        </p>
      </div>

      <ConfigCard />

      {/* Runtime Config */}
      <Card>
        <CardHeader>
          <CardTitle>
            <RefreshCw className="h-4 w-4" />
            Runtime Configuration
          </CardTitle>
          <Button
            variant="ghost"
            size="sm"
            onClick={fetchRuntimeConfig}
            disabled={runtimeLoading}
          >
            {runtimeLoading ? (
              <Loader2 className="h-3 w-3 animate-spin" />
            ) : (
              <RefreshCw className="h-3 w-3" />
            )}
            Refresh
          </Button>
        </CardHeader>
        <CardContent>
          {runtimeError && (
            <div className="mb-4 rounded-lg border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">
              {runtimeError}
            </div>
          )}
          {runtimeConfig ? (
            <div className="grid gap-4 sm:grid-cols-2">
              {RUNTIME_KEYS.map(({ key, label, type, options }) => (
                <div key={key} className="space-y-1.5">
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
                        <Loader2 className="h-3 w-3 animate-spin" />
                      ) : (
                        <Save className="h-3 w-3" />
                      )}
                    </Button>
                  </div>
                  {saveStatus?.key === key && (
                    <div
                      className={`flex items-center gap-1.5 text-xs ${saveStatus.ok ? "text-emerald-500" : "text-destructive"}`}
                    >
                      {saveStatus.ok ? (
                        <CheckCircle2 className="h-3 w-3" />
                      ) : (
                        <AlertCircle className="h-3 w-3" />
                      )}
                      {saveStatus.msg}
                    </div>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="py-8 text-center text-muted-foreground">
              <RefreshCw className="mx-auto mb-2 h-8 w-8 opacity-25" />
              <p className="text-[0.775rem]">
                Click refresh to load runtime config.
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Reset */}
      <Card>
        <CardHeader>
          <CardTitle>
            <Power className="h-4 w-4" />
            Reset Agent
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="mb-3 text-[0.825rem] text-muted-foreground">
            Restart the agent process. This will disconnect all services
            momentarily.
          </p>
          {!resetModal ? (
            <Button
              variant="destructive"
              size="sm"
              onClick={() => setResetModal(true)}
            >
              <Power className="h-3 w-3" />
              Reset Agent
            </Button>
          ) : (
            <div className="space-y-3 rounded-lg border border-destructive/30 bg-destructive/5 px-4 py-3">
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
                    <Loader2 className="h-3 w-3 animate-spin" />
                  ) : (
                    <Power className="h-3 w-3" />
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

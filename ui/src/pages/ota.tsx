// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import { AlertCircle, CheckCircle2, Download, Loader2, RefreshCw, Zap } from "lucide-react";
import { useEffect, useState } from "preact/hooks";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

interface OTAStatus {
  busy: boolean;
  last_error?: string;
}

type BadgeState = "idle" | "running" | "error" | "done";

function statusBadge(status: OTAStatus, submitted: boolean): { label: string; className: string; state: BadgeState } {
  if (status.busy) {
    return { label: "Running", className: "bg-blue-500/15 text-blue-300", state: "running" };
  }
  if (status.last_error) {
    return { label: "Failed", className: "bg-red-500/15 text-red-300", state: "error" };
  }
  if (submitted) {
    return { label: "Triggered", className: "bg-emerald-500/15 text-emerald-300", state: "done" };
  }
  return { label: "Idle", className: "bg-zinc-500/15 text-zinc-300", state: "idle" };
}

export function OTAPage() {
  const [status, setStatus] = useState<OTAStatus>({ busy: false });
  const [submitted, setSubmitted] = useState(false);

  const [url, setUrl] = useState("");
  const [sha256, setSha256] = useState("");
  const [triggering, setTriggering] = useState(false);
  const [triggerError, setTriggerError] = useState("");

  async function pollStatus() {
    try {
      const res = await fetch("/api/ota/status");
      if (res.ok) setStatus(await res.json());
    } catch {
      // network error — keep last known state
    }
  }

  useEffect(() => {
    pollStatus();
    const id = setInterval(pollStatus, 3000);
    return () => clearInterval(id);
  }, []);

  async function handleTrigger(e: Event) {
    e.preventDefault();
    setTriggering(true);
    setTriggerError("");
    try {
      const body: Record<string, string | number> = { url };
      if (sha256.trim()) body.sha256 = sha256.trim();
      const res = await fetch("/api/ota", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        const txt = await res.text();
        throw new Error(txt || `HTTP ${res.status}`);
      }
      setSubmitted(true);
      await pollStatus();
    } catch (e) {
      setTriggerError(String(e));
    } finally {
      setTriggering(false);
    }
  }

  const badge = statusBadge(status, submitted);

  return (
    <div className="space-y-[22px]">
      <div>
        <h1 className="text-[1.35rem] font-bold leading-tight tracking-tight">OTA Update</h1>
        <p className="mt-1 text-[0.825rem] text-muted-foreground">
          Trigger an over-the-air binary update for this gateway agent.
        </p>
      </div>

      {/* Status card */}
      <Card>
        <CardHeader>
          <CardTitle>
            <Zap className="h-4 w-4" />
            Update status
            <span
              className={`ml-auto flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[0.7rem] font-semibold ${badge.className}`}
            >
              {badge.state === "running" && <Loader2 className="h-3 w-3 animate-spin" />}
              {badge.state === "error" && <AlertCircle className="h-3 w-3" />}
              {badge.state === "done" && <CheckCircle2 className="h-3 w-3" />}
              {badge.state === "idle" && <span className="h-1.5 w-1.5 rounded-full bg-current" />}
              {badge.label}
            </span>
            <button
              type="button"
              onClick={pollStatus}
              className="flex h-7 w-7 items-center justify-center rounded-md border border-[var(--border)] hover:bg-white/5"
              title="Refresh status"
            >
              <RefreshCw className="h-3 w-3" />
            </button>
          </CardTitle>
        </CardHeader>
        {status.last_error && (
          <CardContent>
            <div className="rounded-lg border border-destructive/30 bg-destructive/10 px-4 py-3 font-mono text-xs text-destructive">
              {status.last_error}
            </div>
          </CardContent>
        )}
        {status.busy && (
          <CardContent>
            <div className="flex items-center gap-2 text-[0.825rem] text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin text-blue-400" />
              OTA update in progress — the agent will restart automatically when ready.
            </div>
          </CardContent>
        )}
      </Card>

      {/* Trigger form */}
      <Card>
        <CardHeader>
          <CardTitle>
            <Download className="h-4 w-4" />
            Trigger update
          </CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleTrigger} className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="ota-url">Binary URL</Label>
              <Input
                id="ota-url"
                type="url"
                placeholder="https://releases.example.com/agent-v1.2.0-linux-arm64"
                value={url}
                onInput={(e) => setUrl((e.target as HTMLInputElement).value)}
                required
              />
              <p className="text-[0.75rem] text-muted-foreground">
                Direct download URL for the new agent binary. Must be reachable from this gateway.
              </p>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="ota-sha256">
                SHA-256 checksum{" "}
                <span className="text-muted-foreground">(optional)</span>
              </Label>
              <Input
                id="ota-sha256"
                placeholder="e3b0c44298fc1c149afb…"
                value={sha256}
                onInput={(e) => setSha256((e.target as HTMLInputElement).value)}
              />
              <p className="text-[0.75rem] text-muted-foreground">
                Hex-encoded SHA-256 of the binary. The agent will abort if the digest does not match.
              </p>
            </div>
            {triggerError && (
              <p className="text-sm text-destructive">{triggerError}</p>
            )}
            <Button type="submit" disabled={triggering || status.busy}>
              {triggering ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Download className="h-4 w-4" />
              )}
              {triggering ? "Triggering…" : "Trigger OTA update"}
            </Button>
            {status.busy && (
              <p className="text-[0.775rem] text-muted-foreground">
                Another OTA update is already running. Wait for it to complete before triggering a new one.
              </p>
            )}
          </form>
        </CardContent>
      </Card>
    </div>
  );
}

// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import {
  AlertCircle,
  CheckCircle2,
  Download,
  Loader2,
  RefreshCw,
  Sparkles,
  WifiOff,
  Zap,
} from "lucide-react";
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

interface ReleaseAsset {
  name: string;
  browser_download_url: string;
}

interface ReleaseCheck {
  state: "idle" | "checking" | "up-to-date" | "update-available" | "error";
  currentVersion?: string;
  latestVersion?: string;
  assets?: ReleaseAsset[];
  error?: string;
}

function statusBadge(
  status: OTAStatus,
  submitted: boolean,
): { label: string; className: string; state: BadgeState } {
  if (status.busy) {
    return {
      label: "Running",
      className: "bg-blue-500/15 text-blue-300",
      state: "running",
    };
  }
  if (status.last_error) {
    return {
      label: "Failed",
      className: "bg-red-500/15 text-red-300",
      state: "error",
    };
  }
  if (submitted) {
    return {
      label: "Triggered",
      className: "bg-emerald-500/15 text-emerald-300",
      state: "done",
    };
  }
  return {
    label: "Idle",
    className: "bg-zinc-500/15 text-zinc-300",
    state: "idle",
  };
}

// Compare two semver strings (strips leading "v"). Returns true if b > a.
function isNewer(current: string, latest: string): boolean {
  const parse = (v: string) =>
    v
      .replace(/^v/, "")
      .split(".")
      .map((n) => parseInt(n, 10) || 0);
  const [ca, cb, cc] = parse(current);
  const [la, lb, lc] = parse(latest);
  if (la !== ca) return la > ca;
  if (lb !== cb) return lb > cb;
  return lc > cc;
}

// Keep only assets that look like plain binaries (no .sha256, .zip, .tar.gz, .txt, .json).
function isBinaryAsset(name: string): boolean {
  return !/\.(sha256|zip|tar\.gz|tgz|txt|json|deb|rpm|apk)$/i.test(name);
}

export function OTAPage() {
  const [status, setStatus] = useState<OTAStatus>({ busy: false });
  const [submitted, setSubmitted] = useState(false);
  const [pollFailCount, setPollFailCount] = useState(0);

  const [url, setUrl] = useState("");
  const [sha256, setSha256] = useState("");
  const [triggering, setTriggering] = useState(false);
  const [triggerError, setTriggerError] = useState("");

  const [release, setRelease] = useState<ReleaseCheck>({ state: "idle" });

  async function pollStatus() {
    try {
      const res = await fetch("/ota/status");
      if (res.ok) {
        setStatus(await res.json());
        setPollFailCount(0);
      }
    } catch {
      setPollFailCount((n) => n + 1);
    }
  }

  useEffect(() => {
    pollStatus();
    // Only poll while an update is in flight; clear the interval once idle.
    const id = setInterval(async () => {
      await pollStatus();
      setStatus((s) => {
        if (!s.busy) clearInterval(id);
        return s;
      });
    }, 3000);
    return () => clearInterval(id);
  }, []);

  async function checkForUpdates() {
    setRelease({ state: "checking" });
    try {
      const [healthRes, releaseRes] = await Promise.all([
        fetch("/health"),
        fetch("https://api.github.com/repos/absmach/agent/releases/latest", {
          headers: { Accept: "application/vnd.github+json" },
        }),
      ]);

      if (releaseRes.status === 404) {
        setRelease({
          state: "up-to-date",
          currentVersion: "unknown",
          latestVersion: "none",
        });
        return;
      }
      if (!releaseRes.ok) {
        throw new Error(`GitHub API returned HTTP ${releaseRes.status}`);
      }

      const health = healthRes.ok ? await healthRes.json() : {};
      const releaseData = await releaseRes.json();

      const currentVersion: string = health.version ?? "unknown";
      const latestVersion: string = releaseData.tag_name ?? "";
      const assets: ReleaseAsset[] = (releaseData.assets ?? []).filter(
        (a: ReleaseAsset) => isBinaryAsset(a.name),
      );

      const newer =
        currentVersion !== "unknown" &&
        currentVersion !== "0.0.0" &&
        isNewer(currentVersion, latestVersion);

      setRelease({
        state: newer ? "update-available" : "up-to-date",
        currentVersion,
        latestVersion,
        assets,
      });
    } catch (e) {
      setRelease({ state: "error", error: String(e) });
    }
  }

  async function handleTrigger(e: Event) {
    e.preventDefault();
    setTriggering(true);
    setTriggerError("");
    try {
      const body: Record<string, string | number> = { url };
      if (sha256.trim()) body.sha256 = sha256.trim();
      const res = await fetch("/ota", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        let msg = `HTTP ${res.status}`;
        try {
          const txt = await res.text();
          const body = JSON.parse(txt);
          if (body?.error) msg = body.error;
          else if (txt) msg = txt;
        } catch {
          // body is not JSON — msg stays as HTTP status
        }
        throw new Error(msg);
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
        <h1 className="text-[1.35rem] font-bold leading-tight tracking-tight">
          OTA Update
        </h1>
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
              {badge.state === "running" && (
                <Loader2 className="h-3 w-3 animate-spin" />
              )}
              {badge.state === "error" && <AlertCircle className="h-3 w-3" />}
              {badge.state === "done" && <CheckCircle2 className="h-3 w-3" />}
              {badge.state === "idle" && (
                <span className="h-1.5 w-1.5 rounded-full bg-current" />
              )}
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
              OTA update in progress — the agent will restart automatically when
              ready.
            </div>
          </CardContent>
        )}
        {pollFailCount >= 3 && (
          <CardContent>
            <div className="flex items-center gap-1.5 text-[0.75rem] text-amber-500/80">
              <WifiOff className="h-3 w-3 shrink-0" />
              Unable to reach agent — showing last known status
            </div>
          </CardContent>
        )}
      </Card>

      {/* Release check card */}
      <Card>
        <CardHeader>
          <CardTitle>
            <Sparkles className="h-4 w-4" />
            Latest release
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {release.state === "idle" && (
            <p className="text-[0.825rem] text-muted-foreground">
              Check GitHub for the latest published release and pick a binary to
              pre-fill the update form.
            </p>
          )}

          {release.state === "checking" && (
            <div className="flex items-center gap-2 text-[0.825rem] text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" />
              Fetching latest release from GitHub…
            </div>
          )}

          {release.state === "up-to-date" && (
            <div className="flex items-center gap-2 text-[0.825rem] text-emerald-500">
              <CheckCircle2 className="h-4 w-4 shrink-0" />
              {release.latestVersion === "none" ? (
                "No releases have been published yet."
              ) : (
                <>
                  Running{" "}
                  <span className="font-mono font-semibold">
                    {release.currentVersion}
                  </span>{" "}
                  — already on the latest release (
                  <span className="font-mono">{release.latestVersion}</span>).
                </>
              )}
            </div>
          )}

          {release.state === "update-available" && (
            <div className="space-y-3">
              <div className="flex items-center gap-2 text-[0.825rem] text-amber-500">
                <AlertCircle className="h-4 w-4 shrink-0" />
                <span>
                  <span className="font-mono font-semibold">
                    {release.latestVersion}
                  </span>{" "}
                  is available (running{" "}
                  <span className="font-mono">{release.currentVersion}</span>).
                </span>
              </div>
              {release.assets && release.assets.length > 0 && (
                <div className="space-y-1.5">
                  <p className="text-[0.75rem] text-muted-foreground">
                    Select a binary to pre-fill the URL below:
                  </p>
                  <div className="flex flex-wrap gap-2">
                    {release.assets.map((asset) => (
                      <button
                        key={asset.browser_download_url}
                        type="button"
                        onClick={() => setUrl(asset.browser_download_url)}
                        className="rounded-md border px-2.5 py-1 font-mono text-[0.72rem] text-muted-foreground hover:border-primary hover:bg-accent hover:text-foreground"
                      >
                        {asset.name}
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {release.state === "error" && (
            <div className="flex items-start gap-2 text-[0.825rem] text-destructive">
              <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
              <span>{release.error}</span>
            </div>
          )}

          {release.state !== "checking" && (
            <Button variant="outline" size="sm" onClick={checkForUpdates}>
              <RefreshCw className="h-3 w-3" />
              {release.state === "idle" ? "Check for updates" : "Check again"}
            </Button>
          )}
        </CardContent>
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
                placeholder="https://github.com/absmach/agent/releases/download/v1.2.0/agent_linux_arm64"
                value={url}
                onInput={(e) => setUrl((e.target as HTMLInputElement).value)}
                required
              />
              <p className="text-[0.75rem] text-muted-foreground">
                Direct download URL for the new agent binary. Must be reachable
                from this gateway.
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
                Hex-encoded SHA-256 of the binary. The agent will abort if the
                digest does not match.
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
                Another OTA update is already running. Wait for it to complete
                before triggering a new one.
              </p>
            )}
          </form>
        </CardContent>
      </Card>
    </div>
  );
}

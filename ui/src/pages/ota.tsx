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
import { ErrorAlert } from "@/components/error-alert";
import { PageHeader } from "@/components/page-header";
import { StatusBadge, type StatusValue } from "@/components/status-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/components/ui/toaster";

interface OTAStatus {
  busy: boolean;
  last_error?: string;
}

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

function statusToBadge(
  status: OTAStatus,
  submitted: boolean,
): { label: string; state: StatusValue } {
  if (status.busy) return { label: "Running", state: "running" };
  if (status.last_error) return { label: "Failed", state: "error" };
  if (submitted) return { label: "Triggered", state: "triggered" };
  return { label: "Idle", state: "inactive" };
}

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

function isBinaryAsset(name: string): boolean {
  return !/\.(sha256|zip|tar\.gz|tgz|txt|json|deb|rpm|apk)$/i.test(name);
}

export function OTAPage() {
  const { toast } = useToast();
  const [status, setStatus] = useState<OTAStatus>({ busy: false });
  const [submitted, setSubmitted] = useState(false);
  const [pollFailCount, setPollFailCount] = useState(0);

  const [url, setUrl] = useState("");
  const [sha256, setSha256] = useState("");
  const [triggering, setTriggering] = useState(false);
  const [triggerError, setTriggerError] = useState("");

  const [release, setRelease] = useState<ReleaseCheck>({ state: "idle" });
  const [releaseURL, setReleaseURL] = useState(
    "https://api.github.com/repos/absmach/agent/releases/latest",
  );

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
        fetch(releaseURL, {
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
          const parsed = JSON.parse(txt);
          if (parsed?.error) msg = parsed.error;
          else if (txt) msg = txt;
        } catch {
          // body is not JSON
        }
        throw new Error(msg);
      }
      setSubmitted(true);
      toast({ message: "OTA update triggered", variant: "success" });
      await pollStatus();
    } catch (e) {
      setTriggerError(String(e));
      toast({ message: String(e), variant: "error" });
    } finally {
      setTriggering(false);
    }
  }

  const badge = statusToBadge(status, submitted);

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="OTA Update"
        subtitle="Trigger an over-the-air binary update for this gateway agent."
      />

      <Card>
        <CardHeader>
          <CardTitle>
            <Zap className="size-4" />
            Update status
            <StatusBadge
              status={badge.state}
              label={badge.label}
              pulse={badge.state === "running"}
              className="ml-auto"
            />
            <Button
              variant="ghost"
              size="icon"
              className="size-7"
              onClick={pollStatus}
              title="Refresh status"
            >
              <RefreshCw className="size-3" />
            </Button>
          </CardTitle>
        </CardHeader>
        {status.last_error && (
          <CardContent>
            <ErrorAlert error={status.last_error} />
          </CardContent>
        )}
        {status.busy && (
          <CardContent>
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="size-4 animate-spin text-primary" />
              OTA update in progress — the agent will restart automatically when
              ready.
            </div>
          </CardContent>
        )}
        {pollFailCount >= 3 && (
          <CardContent>
            <div className="flex items-center gap-1.5 text-xs text-amber-500">
              <WifiOff className="size-3 shrink-0" />
              Unable to reach agent — showing last known status
            </div>
          </CardContent>
        )}
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>
            <Sparkles className="size-4" />
            Latest release
          </CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          <div className="flex items-center gap-2">
            <Input
              type="url"
              value={releaseURL}
              onInput={(e) =>
                setReleaseURL((e.target as HTMLInputElement).value)
              }
              placeholder="https://api.github.com/repos/owner/repo/releases/latest"
              className="flex-1 text-xs font-mono"
            />
            <Button
              variant="outline"
              size="sm"
              onClick={checkForUpdates}
              disabled={release.state === "checking"}
            >
              {release.state === "checking" ? (
                <Loader2 className="size-3 animate-spin" />
              ) : (
                <RefreshCw className="size-3" />
              )}
              {release.state === "idle" ? "Check" : "Check again"}
            </Button>
          </div>

          {release.state === "idle" && (
            <p className="text-sm text-muted-foreground">
              Check GitHub for the latest published release and pick a binary to
              pre-fill the update form.
            </p>
          )}

          {release.state === "checking" && (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="size-4 animate-spin" />
              Fetching latest release from GitHub…
            </div>
          )}

          {release.state === "up-to-date" && (
            <div className="flex items-center gap-2 text-sm text-success">
              <CheckCircle2 className="size-4 shrink-0" />
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
            <div className="flex flex-col gap-3">
              <div className="flex items-center gap-2 text-sm text-amber-500">
                <AlertCircle className="size-4 shrink-0" />
                <span>
                  <span className="font-mono font-semibold">
                    {release.latestVersion}
                  </span>{" "}
                  is available (running{" "}
                  <span className="font-mono">{release.currentVersion}</span>).
                </span>
              </div>
              {release.assets && release.assets.length > 0 && (
                <div className="flex flex-col gap-1.5">
                  <p className="text-xs text-muted-foreground">
                    Select a binary to pre-fill the URL below:
                  </p>
                  <div className="flex flex-wrap gap-2">
                    {release.assets.map((asset) => (
                      <button
                        key={asset.browser_download_url}
                        type="button"
                        onClick={() => setUrl(asset.browser_download_url)}
                        className="rounded-md border px-2.5 py-1 font-mono text-xs text-muted-foreground transition-colors hover:border-primary hover:bg-accent hover:text-foreground"
                      >
                        {asset.name}
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {release.state === "error" && <ErrorAlert error={release.error} />}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>
            <Download className="size-4" />
            Trigger update
          </CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleTrigger} className="flex flex-col gap-4">
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="ota-url">Binary URL</Label>
              <Input
                id="ota-url"
                type="url"
                placeholder="https://github.com/absmach/agent/releases/download/v1.2.0/agent_linux_arm64"
                value={url}
                onInput={(e) => setUrl((e.target as HTMLInputElement).value)}
                required
              />
              <p className="text-xs text-muted-foreground">
                Direct download URL for the new agent binary. Must be reachable
                from this gateway.
              </p>
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="ota-sha256">
                SHA-256 checksum{" "}
                <span className="font-normal text-muted-foreground">
                  (optional)
                </span>
              </Label>
              <Input
                id="ota-sha256"
                placeholder="e3b0c44298fc1c149afb…"
                value={sha256}
                onInput={(e) => setSha256((e.target as HTMLInputElement).value)}
              />
              <p className="text-xs text-muted-foreground">
                Hex-encoded SHA-256 of the binary. The agent will abort if the
                digest does not match.
              </p>
            </div>
            <ErrorAlert error={triggerError} />
            <Button type="submit" disabled={triggering || status.busy}>
              {triggering ? (
                <Loader2 className="size-4 animate-spin" />
              ) : (
                <Download className="size-4" />
              )}
              {triggering ? "Triggering…" : "Trigger OTA update"}
            </Button>
            {status.busy && (
              <p className="text-xs text-muted-foreground">
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

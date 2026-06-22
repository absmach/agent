// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import {
  AlertCircle,
  CheckCircle2,
  Download,
  FileUp,
  Loader2,
  RefreshCw,
  Sparkles,
  Square,
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/components/ui/toaster";
import { useWSEvent } from "@/lib/agent";
import { formatBytes } from "@/lib/utils";

interface OTAStatus {
  busy: boolean;
  state?: string;
  bytes?: number;
  total?: number;
  progress?: number;
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

async function sha256Hex(data: ArrayBuffer): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function OTAPage() {
  const { toast } = useToast();
  const [status, setStatus] = useState<OTAStatus>({ busy: false });
  const [submitted, setSubmitted] = useState(false);
  const [pollFailCount, setPollFailCount] = useState(0);
  const [aborting, setAborting] = useState(false);

  const [url, setUrl] = useState("");
  const [sha256, setSha256] = useState("");
  const [triggering, setTriggering] = useState(false);
  const [triggerError, setTriggerError] = useState("");

  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [uploadSha, setUploadSha] = useState("");
  const [uploadComputing, setUploadComputing] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState("");

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
    }, 2000);
    return () => clearInterval(id);
  }, []);

  // Refresh status immediately when an OTA WebSocket event arrives, so the
  // progress bar updates in real time instead of waiting for the next poll.
  useWSEvent("ota", () => {
    pollStatus();
  });

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

  async function handleFileSelect(file: File | null) {
    setUploadFile(file);
    setUploadSha("");
    setUploadError("");
    if (!file) return;
    setUploadComputing(true);
    try {
      const buf = await file.arrayBuffer();
      const hash = await sha256Hex(buf);
      setUploadSha(hash);
    } catch {
      setUploadError("Failed to compute SHA-256 checksum in browser.");
    } finally {
      setUploadComputing(false);
    }
  }

  async function handleUpload(e: Event) {
    e.preventDefault();
    if (!uploadFile) return;
    setUploading(true);
    setUploadError("");
    try {
      const hash = uploadSha.trim();
      if (!hash) {
        throw new Error("SHA-256 checksum is required for binary uploads.");
      }
      const buf = await uploadFile.arrayBuffer();
      const res = await fetch(`/ota/data?sha256=${encodeURIComponent(hash)}`, {
        method: "POST",
        headers: { "Content-Type": "application/octet-stream" },
        body: buf,
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
      toast({
        message: "Firmware uploaded — OTA install triggered",
        variant: "success",
      });
      await pollStatus();
    } catch (e) {
      setUploadError(String(e));
      toast({ message: String(e), variant: "error" });
    } finally {
      setUploading(false);
    }
  }

  async function handleAbort() {
    setAborting(true);
    try {
      const res = await fetch("/ota/abort", { method: "POST" });
      if (!res.ok) {
        let msg = `HTTP ${res.status}`;
        try {
          const txt = await res.text();
          const parsed = JSON.parse(txt);
          if (parsed?.error) msg = parsed.error;
        } catch {
          // body is not JSON
        }
        throw new Error(msg);
      }
      toast({ message: "OTA update aborted", variant: "success" });
      await pollStatus();
    } catch (e) {
      toast({ message: String(e), variant: "error" });
    } finally {
      setAborting(false);
    }
  }

  const badge = statusToBadge(status, submitted);
  const progressPct = Math.min(100, Math.max(0, status.progress ?? 0));
  const hasProgress = status.busy;

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
        {hasProgress && (
          <CardContent>
            <div className="flex flex-col gap-2">
              <div className="flex items-center justify-between text-sm">
                <span className="font-mono capitalize text-muted-foreground">
                  {status.state ?? "working"}
                </span>
                <span className="font-mono text-muted-foreground">
                  {formatBytes(status.bytes)}
                  {status.total ? ` / ${formatBytes(status.total)}` : ""}
                </span>
              </div>
              <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
                <div
                  className="h-full rounded-full bg-primary transition-all duration-300"
                  style={{ width: `${progressPct}%` }}
                />
              </div>
              <div className="flex items-center justify-between">
                <span className="text-xs text-muted-foreground">
                  {progressPct.toFixed(0)}% complete
                </span>
                {status.busy && (
                  <Button
                    variant="destructive"
                    size="sm"
                    onClick={handleAbort}
                    disabled={aborting}
                  >
                    {aborting ? (
                      <Loader2 className="size-3 animate-spin" />
                    ) : (
                      <Square className="size-3" />
                    )}
                    Abort
                  </Button>
                )}
              </div>
            </div>
          </CardContent>
        )}
        {status.busy && !hasProgress && (
          <CardContent>
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <Loader2 className="size-4 animate-spin text-primary" />
                OTA update in progress — the agent will restart automatically
                when ready.
              </div>
              <Button
                variant="destructive"
                size="sm"
                onClick={handleAbort}
                disabled={aborting}
              >
                {aborting ? (
                  <Loader2 className="size-3 animate-spin" />
                ) : (
                  <Square className="size-3" />
                )}
                Abort
              </Button>
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
          <Tabs defaultValue="url">
            <TabsList>
              <TabsTrigger value="url">
                <Download className="mr-1.5 size-3.5" />
                Download from URL
              </TabsTrigger>
              <TabsTrigger value="upload">
                <FileUp className="mr-1.5 size-3.5" />
                Upload binary
              </TabsTrigger>
            </TabsList>

            <TabsContent value="url">
              <form onSubmit={handleTrigger} className="flex flex-col gap-4">
                <div className="flex flex-col gap-1.5">
                  <Label htmlFor="ota-url">Binary URL</Label>
                  <Input
                    id="ota-url"
                    type="url"
                    placeholder="https://github.com/absmach/agent/releases/download/v1.2.0/agent_linux_arm64"
                    value={url}
                    onInput={(e) =>
                      setUrl((e.target as HTMLInputElement).value)
                    }
                    required
                  />
                  <p className="text-xs text-muted-foreground">
                    Direct download URL for the new agent binary. Must be
                    reachable from this gateway.
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
                    onInput={(e) =>
                      setSha256((e.target as HTMLInputElement).value)
                    }
                  />
                  <p className="text-xs text-muted-foreground">
                    Hex-encoded SHA-256 of the binary. The agent will abort if
                    the digest does not match.
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
                    Another OTA update is already running. Wait for it to
                    complete or abort it before triggering a new one.
                  </p>
                )}
              </form>
            </TabsContent>

            <TabsContent value="upload">
              <form onSubmit={handleUpload} className="flex flex-col gap-4">
                <div className="flex flex-col gap-1.5">
                  <Label htmlFor="ota-file">Firmware binary</Label>
                  <Input
                    id="ota-file"
                    type="file"
                    accept="application/octet-stream"
                    onInput={(e) =>
                      handleFileSelect(
                        (e.target as HTMLInputElement).files?.[0] ?? null,
                      )
                    }
                    required
                  />
                  <p className="text-xs text-muted-foreground">
                    Upload a firmware binary directly to the agent over HTTP.
                    This is the HTTP equivalent of MQTT data delivery — useful
                    when the gateway has no outbound internet access.
                  </p>
                </div>
                {uploadFile && (
                  <div className="rounded-md border bg-muted/40 px-3 py-2 text-xs text-muted-foreground">
                    <span className="font-medium text-foreground">
                      {uploadFile.name}
                    </span>{" "}
                    · {formatBytes(uploadFile.size)}
                  </div>
                )}
                <div className="flex flex-col gap-1.5">
                  <Label htmlFor="ota-upload-sha">
                    SHA-256 checksum{" "}
                    {uploadComputing && (
                      <span className="font-normal text-muted-foreground">
                        (computing…)
                      </span>
                    )}
                  </Label>
                  <Input
                    id="ota-upload-sha"
                    placeholder="auto-computed from selected file"
                    value={uploadSha}
                    onInput={(e) =>
                      setUploadSha((e.target as HTMLInputElement).value)
                    }
                    className="font-mono text-xs"
                    readOnly={uploadComputing}
                    required
                  />
                  <p className="text-xs text-muted-foreground">
                    Auto-computed from the selected file. A valid hash is
                    required — the agent will reject the payload if it does not
                    match.
                  </p>
                </div>
                <ErrorAlert error={uploadError} />
                <Button
                  type="submit"
                  disabled={
                    uploading ||
                    status.busy ||
                    !uploadFile ||
                    !uploadSha.trim() ||
                    uploadComputing
                  }
                >
                  {uploading ? (
                    <Loader2 className="size-4 animate-spin" />
                  ) : (
                    <FileUp className="size-4" />
                  )}
                  {uploading ? "Uploading…" : "Upload & install"}
                </Button>
                {status.busy && (
                  <p className="text-xs text-muted-foreground">
                    Another OTA update is already running. Wait for it to
                    complete or abort it before uploading new firmware.
                  </p>
                )}
              </form>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
}

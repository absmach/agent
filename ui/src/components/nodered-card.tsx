// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import {
  Activity,
  AlertCircle,
  FileJson,
  List,
  Loader2,
  Network,
  Play,
  Plus,
  RefreshCw,
  Upload,
  X,
} from "lucide-react";
import { useEffect, useRef, useState } from "preact/hooks";
import { EmptyState } from "@/components/empty-state";
import { StatusBadge, type StatusValue } from "@/components/status-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { useToast } from "@/components/ui/toaster";

type NodeRedCmd =
  | "nodered-ping"
  | "nodered-state"
  | "nodered-flows"
  | "nodered-deploy"
  | "nodered-add-flow";

interface FlowItem {
  id?: string;
  type?: string;
  label?: string;
  name?: string;
  z?: string;
}

export function NodeRedCard() {
  const { toast } = useToast();
  const [loading, setLoading] = useState(false);
  const [lastCmd, setLastCmd] = useState("");
  const [response, setResponse] = useState("");
  const [nodeRedStatus, setNodeRedStatus] = useState<
    "unknown" | "online" | "offline"
  >("unknown");
  const [flowCount, setFlowCount] = useState("—");
  const [lastFetched, setLastFetched] = useState("never");
  const [flowItems, setFlowItems] = useState<FlowItem[]>([]);
  const [flows, setFlows] = useState("");
  const [fileName, setFileName] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    async function init() {
      setLoading(true);
      try {
        const [pingRes, flowsRes] = await Promise.all([
          fetch("/nodered", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ command: "nodered-ping", flows: "" }),
          }),
          fetch("/nodered", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ command: "nodered-flows", flows: "" }),
          }),
        ]);
        setNodeRedStatus(pingRes.ok ? "online" : "offline");
        if (flowsRes.ok) {
          const data = await flowsRes.json();
          updateFlowList(data.response ?? "");
        }
      } catch {
        setNodeRedStatus("offline");
      } finally {
        setLoading(false);
      }
    }
    init();
  }, []);

  async function send(cmd: NodeRedCmd, label: string) {
    if ((cmd === "nodered-deploy" || cmd === "nodered-add-flow") && !flows) {
      setLastCmd(label);
      setResponse("ERROR: No flow file selected. Upload a JSON file first.");
      toast({ message: "No flow file selected", variant: "warning" });
      return;
    }

    setLoading(true);
    setLastCmd(label);
    setResponse("");
    try {
      const res = await fetch("/nodered", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ command: cmd, flows }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      const raw = data.response ?? JSON.stringify(data);
      if (cmd === "nodered-ping") {
        setNodeRedStatus("online");
      }
      if (cmd === "nodered-flows") {
        updateFlowList(raw);
      }
      if (cmd === "nodered-deploy" || cmd === "nodered-add-flow") {
        toast({ message: `${label} successful`, variant: "success" });
      }
      try {
        setResponse(JSON.stringify(JSON.parse(raw), null, 2));
      } catch {
        setResponse(raw);
      }
    } catch (err) {
      if (cmd === "nodered-ping") {
        setNodeRedStatus("offline");
      }
      setResponse(String(err));
      toast({ message: String(err), variant: "error" });
    } finally {
      setLoading(false);
    }
  }

  function updateFlowList(raw: string) {
    try {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        const items = parsed.filter(
          (flow): flow is FlowItem => flow && typeof flow === "object",
        );
        setFlowItems(items);
        setFlowCount(String(items.length));
        setLastFetched("just now");
      }
    } catch {
      setFlowItems([]);
      setFlowCount("—");
    }
  }

  function handleFileChange(e: Event) {
    const file = (e.target as HTMLInputElement).files?.[0];
    if (!file) return;
    setFileName(file.name);
    const reader = new FileReader();
    reader.onload = (ev) => {
      const content = ev.target?.result as string;
      setFlows(btoa(unescape(encodeURIComponent(content))));
    };
    reader.readAsText(file);
  }

  const statusState: StatusValue =
    nodeRedStatus === "online"
      ? "online"
      : nodeRedStatus === "offline"
        ? "offline"
        : "unknown";
  const statusLabel = {
    unknown: "Unknown",
    online: "Online",
    offline: "Offline",
  }[nodeRedStatus];

  return (
    <div className="flex flex-col gap-4">
      <section className="grid gap-3.5 md:grid-cols-2">
        <div className="rounded-xl border bg-card px-4 py-3.5 shadow-sm">
          <div className="mb-2 text-xs font-bold uppercase tracking-wide text-muted-foreground">
            Node-RED Status
          </div>
          <div className="flex items-center justify-between">
            <span className="text-base font-bold tracking-tight">
              {statusLabel}
            </span>
            <StatusBadge
              status={statusState}
              label={
                nodeRedStatus === "online"
                  ? "Reachable"
                  : nodeRedStatus === "offline"
                    ? "Not reachable"
                    : "Not pinged yet"
              }
            />
          </div>
        </div>
        <div className="rounded-xl border bg-card px-4 py-3.5 shadow-sm">
          <div className="mb-2 text-xs font-bold uppercase tracking-wide text-muted-foreground">
            Deployed Flows
          </div>
          <div className="text-2xl font-bold leading-none tracking-tight">
            {flowCount}
          </div>
          <div className="mt-1 text-xs text-muted-foreground">
            last fetched: {lastFetched}
          </div>
        </div>
      </section>

      <Card>
        <CardHeader>
          <CardTitle>
            <Network className="size-4" />
            Controls
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap items-center gap-2">
            <Button
              variant="outline"
              onClick={() => send("nodered-ping", "Ping")}
              disabled={loading}
            >
              <Activity className="size-3" />
              Ping
            </Button>
            <Button
              variant="outline"
              onClick={() => send("nodered-state", "Get State")}
              disabled={loading}
            >
              <AlertCircle className="size-3" />
              Get State
            </Button>
            <Button
              variant="outline"
              onClick={() => send("nodered-flows", "Get Flows")}
              disabled={loading}
            >
              <List className="size-3" />
              Get Flows
            </Button>
            <Separator orientation="vertical" className="h-5" />
            <Button
              onClick={() => send("nodered-deploy", "Deploy Flows")}
              disabled={loading}
            >
              <Play className="size-3" />
              Deploy Flows
            </Button>
            <Button
              variant="outline"
              onClick={() => send("nodered-add-flow", "Add Flow")}
              disabled={loading}
            >
              <Plus className="size-3" />
              Add Flow
            </Button>
          </div>

          {(loading || response) && (
            <pre className="mt-2.5 max-h-30 overflow-y-auto rounded-lg bg-zinc-950 px-3.5 py-2.5 font-mono text-xs leading-relaxed text-zinc-400">
              {loading ? (
                <span className="flex items-center gap-2">
                  <Loader2 className="size-3.5 animate-spin" />
                  {lastCmd}...
                </span>
              ) : (
                response
              )}
            </pre>
          )}

          <Separator className="my-4" />
          <div className="mb-2 text-xs font-bold uppercase tracking-wide text-muted-foreground">
            Upload Flow File
          </div>

          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            className="w-full rounded-xl border-2 border-dashed bg-transparent px-6 py-6 text-center text-sm text-muted-foreground transition hover:border-primary hover:bg-accent"
          >
            <Upload className="mx-auto mb-2 size-6 opacity-50" />
            <div className="mt-1 font-semibold text-foreground">
              Drop a JSON flow file here
            </div>
            <div className="mt-0.5 text-xs">or click to browse</div>
          </button>
          <div className="mt-2 text-xs text-muted-foreground">
            {fileName || "No file selected"}
          </div>
          <input
            ref={fileInputRef}
            type="file"
            accept=".json,application/json"
            className="hidden"
            onChange={handleFileChange}
          />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>
            <FileJson className="size-4" />
            Flow List
          </CardTitle>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => send("nodered-flows", "Get Flows")}
            disabled={loading}
          >
            <RefreshCw className="size-3" />
            Refresh
          </Button>
        </CardHeader>
        <div>
          {flowItems.length > 0 ? (
            flowItems.map((flow) => (
              <div
                key={flow.id ?? `${flow.type}-${flow.name}-${flow.label}`}
                className="flex items-center gap-3 border-b px-4 py-3 last:border-b-0"
              >
                <div className="flex size-8 shrink-0 items-center justify-center rounded-md bg-accent text-primary">
                  <FileJson className="size-3.5" />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="text-sm font-semibold">
                    {flow.label || flow.name || flow.type || "Unnamed flow"}
                  </div>
                  <div className="truncate font-mono text-xs text-muted-foreground">
                    {flow.id ?? "no id"}
                    {flow.type ? ` · ${flow.type}` : ""}
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => setResponse(JSON.stringify(flow, null, 2))}
                  className="inline-flex items-center gap-1 rounded-lg border px-2.5 py-1 text-xs font-semibold text-muted-foreground transition-colors hover:bg-secondary hover:text-foreground"
                >
                  Details
                </button>
              </div>
            ))
          ) : (
            <EmptyState
              icon={<FileJson className="size-8" />}
              title="No flows loaded"
              description='Click "Get Flows" or deploy a JSON file to populate this list.'
            />
          )}
        </div>
      </Card>

      {response && !loading && (
        <button
          type="button"
          onClick={() => setResponse("")}
          className="inline-flex items-center gap-1 text-xs text-muted-foreground transition-colors hover:text-foreground"
        >
          <X className="size-3" />
          Clear response
        </button>
      )}
    </div>
  );
}

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
import { useRef, useState } from "preact/hooks";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

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

  async function send(cmd: NodeRedCmd, label: string) {
    if ((cmd === "nodered-deploy" || cmd === "nodered-add-flow") && !flows) {
      setLastCmd(label);
      setResponse("ERROR: No flow file selected. Upload a JSON file first.");
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

  const statusMeta = {
    unknown: {
      label: "Unknown",
      badge: "● Not pinged yet",
      className: "bg-amber-50 text-amber-700 dark:bg-amber-950",
    },
    online: {
      label: "Online",
      badge: "● Reachable",
      className: "bg-emerald-50 text-emerald-700 dark:bg-emerald-950",
    },
    offline: {
      label: "Offline",
      badge: "● Not reachable",
      className: "bg-red-50 text-red-600 dark:bg-red-950",
    },
  }[nodeRedStatus];

  return (
    <div className="space-y-3.5">
      <section className="grid gap-3.5 md:grid-cols-2">
        <div className="rounded-xl border bg-card px-[18px] py-[15px] shadow-sm">
          <div className="mb-2 text-[0.65rem] font-bold uppercase tracking-[0.07em] text-muted-foreground">
            Node-RED Status
          </div>
          <div className="text-[0.95rem] font-bold leading-none tracking-tight">
            {statusMeta.label}
          </div>
          <div
            className={`mt-2 inline-flex rounded-full px-2 py-0.5 text-[0.68rem] font-semibold ${statusMeta.className}`}
          >
            {statusMeta.badge}
          </div>
        </div>
        <div className="rounded-xl border bg-card px-[18px] py-[15px] shadow-sm">
          <div className="mb-2 text-[0.65rem] font-bold uppercase tracking-[0.07em] text-muted-foreground">
            Deployed Flows
          </div>
          <div className="text-[1.4rem] font-bold leading-none tracking-tight">
            {flowCount}
          </div>
          <div className="mt-1 text-[0.7rem] text-muted-foreground">
            last fetched: {lastFetched}
          </div>
        </div>
      </section>

      <Card>
        <CardHeader>
          <CardTitle>
            <Network className="h-4 w-4" />
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
              <Activity className="h-3 w-3" />
              Ping
            </Button>
            <Button
              variant="outline"
              onClick={() => send("nodered-state", "Get State")}
              disabled={loading}
            >
              <AlertCircle className="h-3 w-3" />
              Get State
            </Button>
            <Button
              variant="outline"
              onClick={() => send("nodered-flows", "Get Flows")}
              disabled={loading}
            >
              <List className="h-3 w-3" />
              Get Flows
            </Button>
            <span className="h-[18px] w-px bg-border" />
            <Button
              onClick={() => send("nodered-deploy", "Deploy Flows")}
              disabled={loading}
            >
              <Play className="h-3 w-3" />
              Deploy Flows
            </Button>
            <Button
              variant="outline"
              onClick={() => send("nodered-add-flow", "Add Flow")}
              disabled={loading}
            >
              <Plus className="h-3 w-3" />
              Add Flow
            </Button>
          </div>

          {(loading || response) && (
            <pre className="mt-2.5 max-h-[120px] overflow-y-auto rounded-lg bg-zinc-950 px-3.5 py-2.5 font-mono text-[0.75rem] leading-relaxed text-zinc-400">
              {loading ? (
                <span className="flex items-center gap-2">
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  {lastCmd}...
                </span>
              ) : (
                response
              )}
            </pre>
          )}

          <div className="my-[18px] h-px bg-border" />
          <div className="mb-2 text-[0.65rem] font-bold uppercase tracking-[0.07em] text-muted-foreground">
            Upload Flow File
          </div>

          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            className="w-full rounded-xl border-2 border-dashed bg-transparent px-6 py-[26px] text-center text-[0.8rem] text-muted-foreground transition hover:border-primary hover:bg-accent"
          >
            <Upload className="mx-auto mb-2 h-[26px] w-[26px] opacity-50" />
            <div className="mt-1 font-semibold text-foreground">
              Drop a JSON flow file here
            </div>
            <div className="mt-0.5 text-[0.72rem]">or click to browse</div>
          </button>
          <div className="mt-2 text-[0.75rem] text-muted-foreground">
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
            <FileJson className="h-4 w-4" />
            Flow List
          </CardTitle>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => send("nodered-flows", "Get Flows")}
            disabled={loading}
          >
            <RefreshCw className="h-3 w-3" />
            Refresh
          </Button>
        </CardHeader>
        <div>
          {flowItems.length > 0 ? (
            flowItems.map((flow) => (
              <div
                key={flow.id ?? `${flow.type}-${flow.name}-${flow.label}`}
                className="flex items-center gap-[13px] border-b px-[18px] py-[13px] last:border-b-0"
              >
                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-accent text-primary">
                  <FileJson className="h-3.5 w-3.5" />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="text-[0.825rem] font-semibold">
                    {flow.label || flow.name || flow.type || "Unnamed flow"}
                  </div>
                  <div className="truncate font-mono text-[0.7rem] text-muted-foreground">
                    {flow.id ?? "no id"}
                    {flow.type ? ` · ${flow.type}` : ""}
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => setResponse(JSON.stringify(flow, null, 2))}
                  className="inline-flex items-center gap-1 rounded-lg border px-2.5 py-1 text-[0.75rem] font-semibold text-muted-foreground hover:bg-secondary hover:text-foreground"
                >
                  Details
                </button>
              </div>
            ))
          ) : (
            <div className="px-6 py-11 text-center text-muted-foreground">
              <FileJson className="mx-auto mb-2.5 h-[34px] w-[34px] opacity-25" />
              <h3 className="mb-1 text-[0.85rem] font-semibold text-foreground">
                No flows loaded
              </h3>
              <p className="text-[0.775rem]">
                Click "Get Flows" or deploy a JSON file to populate this list.
              </p>
            </div>
          )}
        </div>
      </Card>

      {response && !loading && (
        <button
          type="button"
          onClick={() => setResponse("")}
          className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
        >
          <X className="h-3 w-3" />
          Clear response
        </button>
      )}
    </div>
  );
}

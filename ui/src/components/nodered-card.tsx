// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { CheckCircle, FileJson, Loader2, Network, X } from "lucide-react";
import { useRef, useState } from "preact/hooks";

type NodeRedCmd =
  | "nodered-ping"
  | "nodered-state"
  | "nodered-flows"
  | "nodered-deploy"
  | "nodered-add-flow";

export function NodeRedCard() {
  const [loading, setLoading] = useState(false);
  const [lastCmd, setLastCmd] = useState("");
  const [response, setResponse] = useState("");
  const [flows, setFlows] = useState("");
  const [fileName, setFileName] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);

  async function send(cmd: NodeRedCmd, label: string) {
    setLoading(true);
    setLastCmd(label);
    setResponse("");
    try {
      const res = await fetch("/nodered", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ command: cmd, flows }),
      });
      const data = await res.json();
      const raw = data.response ?? JSON.stringify(data);
      try {
        setResponse(JSON.stringify(JSON.parse(raw), null, 2));
      } catch {
        setResponse(raw);
      }
    } catch (err) {
      setResponse(String(err));
    } finally {
      setLoading(false);
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

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <Network className="h-4 w-4" />
          Node-RED
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex flex-wrap gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => send("nodered-ping", "Ping")}
            disabled={loading}
          >
            Ping
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => send("nodered-state", "State")}
            disabled={loading}
          >
            State
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => send("nodered-flows", "Get Flows")}
            disabled={loading}
          >
            Get Flows
          </Button>
        </div>

        <div className="space-y-2">
          <div className="flex items-center gap-3">
            <Button
              variant="outline"
              size="sm"
              onClick={() => fileInputRef.current?.click()}
            >
              <FileJson className="h-4 w-4" />
              Select JSON File
            </Button>
            {fileName ? (
              <span className="flex items-center gap-1 text-sm text-success">
                <CheckCircle className="h-3.5 w-3.5" />
                {fileName}
              </span>
            ) : (
              <span className="text-sm text-muted-foreground">
                No file selected
              </span>
            )}
          </div>
          <input
            ref={fileInputRef}
            type="file"
            accept="application/json"
            className="hidden"
            onChange={handleFileChange}
          />
        </div>

        <div className="flex gap-2">
          <Button
            size="sm"
            onClick={() => send("nodered-deploy", "Deploy")}
            disabled={loading || !flows}
          >
            Deploy Flows
          </Button>
          <Button
            variant="success"
            size="sm"
            onClick={() => send("nodered-add-flow", "Add Flow")}
            disabled={loading || !flows}
          >
            Add Flow
          </Button>
        </div>

        {loading && (
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" />
            Loading...
          </div>
        )}

        {!loading && response && (
          <div className="space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                {lastCmd} Response
              </span>
              <button
                type="button"
                onClick={() => setResponse("")}
                className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
              >
                <X className="h-3 w-3" />
                Clear
              </button>
            </div>
            <pre className="max-h-56 overflow-y-auto rounded-md border bg-muted/50 p-3 text-xs">
              {response}
            </pre>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

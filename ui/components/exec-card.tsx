"use client";

import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Terminal, X } from "lucide-react";
import { useState } from "react";

export function ExecCard() {
  const [cmd, setCmd] = useState("");
  const [lastCmd, setLastCmd] = useState("");
  const [output, setOutput] = useState("");
  const [loading, setLoading] = useState(false);

  async function run() {
    if (!cmd.trim()) return;
    setLoading(true);
    setLastCmd(cmd);
    setOutput("");
    try {
      const res = await fetch("/api/exec", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          bn: "exec:",
          n: "exec",
          vs: cmd,
        }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setOutput(data.vs ?? JSON.stringify(data, null, 2));
    } catch (err) {
      setOutput(String(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <Terminal className="h-4 w-4" />
          Execute Command
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-1.5">
          <Label htmlFor="execCmd">Command</Label>
          <Input
            id="execCmd"
            placeholder="e.g. ls,-la"
            value={cmd}
            onChange={(e) => setCmd(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && run()}
          />
          <p className="text-xs text-muted-foreground">
            Comma-separated: command,arg1,arg2
          </p>
        </div>

        <Button
          variant="destructive"
          size="sm"
          onClick={run}
          disabled={loading || !cmd.trim()}
        >
          {loading ? "Running…" : "Run"}
        </Button>

        {output && (
          <div className="space-y-1">
            <div className="flex items-center justify-between">
              <span className="font-mono text-xs text-muted-foreground">
                $ {lastCmd}
              </span>
              <button
                type="button"
                onClick={() => setOutput("")}
                className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
              >
                <X className="h-3 w-3" />
                Clear
              </button>
            </div>
            <pre className="max-h-64 overflow-y-auto rounded-md bg-zinc-900 p-3 text-xs text-zinc-100 whitespace-pre-wrap break-all">
              {output}
            </pre>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

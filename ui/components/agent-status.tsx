"use client";

import { useEffect, useState } from "react";

type Status = "checking" | "online" | "offline";

export function AgentStatus() {
  const [status, setStatus] = useState<Status>("checking");
  const [agentUrl, setAgentUrl] = useState("…");

  async function check() {
    try {
      const res = await fetch("/api/health");
      const data = await res.json();
      setAgentUrl(data.agentUrl ?? "unknown");
      setStatus(data.reachable ? "online" : "offline");
    } catch {
      setStatus("offline");
    }
  }

  useEffect(() => {
    check();
    // Retry every 5 seconds so the UI recovers automatically when the agent starts
    const id = setInterval(check, 5000);
    return () => clearInterval(id);
  }, []);

  const styles: Record<Status, { dot: string; text: string; label: string }> = {
    checking: {
      dot: "bg-muted-foreground animate-pulse",
      text: "text-muted-foreground",
      label: "Checking agent…",
    },
    online: {
      dot: "bg-success",
      text: "text-success",
      label: "Agent is reachable",
    },
    offline: {
      dot: "bg-destructive",
      text: "text-destructive",
      label: "Agent is not reachable",
    },
  };

  const { dot, text, label } = styles[status];

  return (
    <div className="flex items-center gap-2 rounded-lg border bg-card px-4 py-3 text-sm w-fit">
      <span className={`h-2 w-2 rounded-full shrink-0 ${dot}`} />
      <span className={`font-medium ${text}`}>{label}</span>
      <span className="text-muted-foreground">
        — connecting to{" "}
        <code className="rounded bg-muted px-1 py-0.5 text-xs font-mono">
          {agentUrl}
        </code>
      </span>
    </div>
  );
}

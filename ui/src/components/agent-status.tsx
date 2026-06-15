// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import { AlertCircle, CheckCircle2 } from "lucide-react";
import { useEffect, useState } from "preact/hooks";
import { Alert } from "@/components/ui/alert";

type Status = "checking" | "online" | "offline";

export function AgentStatus() {
  const [status, setStatus] = useState<Status>("checking");
  const [agentUrl, setAgentUrl] = useState("...");

  async function check() {
    setAgentUrl(window.location.origin);
    try {
      const res = await fetch("/config", {
        cache: "no-store",
        signal: AbortSignal.timeout(3000),
      });
      setStatus(res.ok ? "online" : "offline");
    } catch {
      setStatus("offline");
    }
  }

  useEffect(() => {
    check();
    const id = setInterval(check, 5000);
    return () => clearInterval(id);
  }, []);

  const online = status === "online";

  return (
    <Alert variant={online ? "success" : "destructive"} className="items-start">
      {online ? (
        <CheckCircle2 className="mt-0.5 size-4 shrink-0" />
      ) : (
        <AlertCircle className="mt-0.5 size-4 shrink-0" />
      )}
      <span className="text-sm">
        {online ? "Agent is reachable" : "Agent is not reachable"}
        {" — connecting to "}
        <code className="rounded bg-black/5 px-1 py-0.5 font-mono text-[0.85em] dark:bg-white/10">
          {agentUrl}
        </code>
      </span>
    </Alert>
  );
}

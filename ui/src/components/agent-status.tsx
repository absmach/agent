// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import { AlertCircle } from "lucide-react";
import { useEffect, useState } from "preact/hooks";

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
    <div
      className={`flex items-start gap-2.5 rounded-lg border px-4 py-3 text-[0.825rem] ${
        online
          ? "border-emerald-600/20 bg-emerald-50 text-emerald-700 dark:bg-emerald-950 dark:text-emerald-300"
          : "border-red-600/20 bg-red-50 text-red-600 dark:bg-red-950 dark:text-red-300"
      }`}
    >
      <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
      <span>
        {online ? "Agent is reachable" : "Agent is not reachable"}
        {" - connecting to "}
        <code className="rounded bg-black/5 px-1 py-0.5 font-mono text-[0.8em] dark:bg-white/10">
          {agentUrl}
        </code>
      </span>
    </div>
  );
}

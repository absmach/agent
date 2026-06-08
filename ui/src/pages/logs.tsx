// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import { useEffect, useRef, useState } from "preact/hooks";

type Level = "DEBUG" | "INFO" | "WARN" | "ERROR" | "unknown";

function parseLevel(line: string): Level {
  if (line.includes(" DEBUG ")) return "DEBUG";
  if (line.includes(" INFO ")) return "INFO";
  if (line.includes(" WARN ")) return "WARN";
  if (line.includes(" ERROR ")) return "ERROR";
  return "unknown";
}

function levelClass(level: Level): string {
  switch (level) {
    case "DEBUG":
      return "text-zinc-500";
    case "INFO":
      return "text-emerald-400";
    case "WARN":
      return "text-yellow-400";
    case "ERROR":
      return "text-red-400";
    default:
      return "text-zinc-300";
  }
}

export function LogsPage() {
  const [lines, setLines] = useState<string[]>([]);
  const [paused, setPaused] = useState(false);
  const [connected, setConnected] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);
  const pausedRef = useRef(false);

  pausedRef.current = paused;

  useEffect(() => {
    const es = new EventSource("/logs");

    es.onopen = () => setConnected(true);

    es.onmessage = (e) => {
      if (!pausedRef.current) {
        setLines((prev) => [...prev.slice(-999), e.data as string]);
      }
    };

    es.onerror = () => setConnected(false);

    return () => es.close();
  }, []);

  useEffect(() => {
    if (!paused) {
      bottomRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [lines, paused]);

  return (
    <div className="flex h-full flex-col gap-4 p-4 sm:p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold">Agent Logs</h1>
          <p className="text-sm text-[var(--muted)]">
            Live log stream from the agent process
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span
            className={`flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[0.7rem] font-semibold ${
              connected
                ? "bg-emerald-500/15 text-emerald-300"
                : "bg-red-500/15 text-red-300"
            }`}
          >
            <span className="h-1.5 w-1.5 rounded-full bg-current" />
            {connected ? "Streaming" : "Disconnected"}
          </span>
          <button
            type="button"
            onClick={() => setPaused((p) => !p)}
            className="rounded-md border border-[var(--border)] bg-[var(--card-bg)] px-3 py-1.5 text-xs font-medium hover:bg-white/5 transition-colors"
          >
            {paused ? "Resume" : "Pause"}
          </button>
          <button
            type="button"
            onClick={() => setLines([])}
            className="rounded-md border border-[var(--border)] bg-[var(--card-bg)] px-3 py-1.5 text-xs font-medium hover:bg-white/5 transition-colors"
          >
            Clear
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-hidden rounded-xl border border-[var(--border)] shadow-sm">
        <div className="flex items-center gap-2 bg-zinc-800 px-4 py-2.5">
          <div className="flex gap-1.5">
            <span className="h-3 w-3 rounded-full bg-red-500" />
            <span className="h-3 w-3 rounded-full bg-yellow-400" />
            <span className="h-3 w-3 rounded-full bg-green-500" />
          </div>
          <span className="mx-auto font-mono text-xs text-zinc-400">
            magistrala-agent — logs
          </span>
          <span className="text-xs text-zinc-500">{lines.length} lines</span>
        </div>

        <div className="h-[calc(100vh-260px)] overflow-y-auto bg-zinc-900 p-4 font-mono text-xs leading-relaxed">
          {lines.length === 0 ? (
            <p className="text-zinc-500">
              {connected
                ? "Waiting for log entries…"
                : "Connecting to log stream…"}
            </p>
          ) : (
            lines.map((line, i) => {
              const level = parseLevel(line);
              return (
                <div
                  key={i}
                  className={`whitespace-pre-wrap break-all ${levelClass(level)}`}
                >
                  {line}
                </div>
              );
            })
          )}
          <div ref={bottomRef} />
        </div>
      </div>
    </div>
  );
}

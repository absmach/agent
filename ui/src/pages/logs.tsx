// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import { Search } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "preact/hooks";
import { StatusBadge } from "@/components/status-badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";

const TIME_OPTIONS = [
  { value: "0", label: "All time" },
  { value: "60", label: "Last 1m" },
  { value: "300", label: "Last 5m" },
  { value: "900", label: "Last 15m" },
  { value: "1800", label: "Last 30m" },
  { value: "3600", label: "Last 1h" },
] as const;

function parseTimeSeconds(line: string): number | null {
  const m = line.match(/^(\d{2}):(\d{2}):(\d{2})/);
  if (!m) return null;
  return Number(m[1]) * 3600 + Number(m[2]) * 60 + Number(m[3]);
}

function secondsSince(lineSeconds: number, nowSeconds: number): number {
  return lineSeconds <= nowSeconds
    ? nowSeconds - lineSeconds
    : 86400 - lineSeconds + nowSeconds;
}

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
  const [levelFilter, setLevelFilter] = useState<Level | "ALL">("ALL");
  const [search, setSearch] = useState("");
  const [timeFilter, setTimeFilter] = useState<number>(0);
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

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    const nowSec = Math.floor(Date.now() / 1000) % 86400;
    return lines.filter((line) => {
      if (levelFilter !== "ALL" && parseLevel(line) !== levelFilter)
        return false;
      if (q && !line.toLowerCase().includes(q)) return false;
      if (timeFilter > 0) {
        const ls = parseTimeSeconds(line);
        if (ls === null || secondsSince(ls, nowSec) > timeFilter)
          return false;
      }
      return true;
    });
  }, [lines, levelFilter, search, timeFilter]);

  return (
    <div className="flex h-full flex-col gap-4 p-4 sm:p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold">Agent Logs</h1>
          <p className="text-sm text-muted-foreground">
            Live log stream from the agent process
          </p>
        </div>
        <div className="flex items-center gap-2">
          <StatusBadge
            status={connected ? "online" : "offline"}
            label={connected ? "Streaming" : "Disconnected"}
            pulse={connected}
          />
          <div className="flex items-center gap-2">
            <div className="relative">
              <Search className="pointer-events-none absolute left-2.5 top-2.5 size-4 text-muted-foreground" />
              <Input
                type="text"
                placeholder="Search logs…"
                value={search}
                onInput={(e) => setSearch((e.target as HTMLInputElement).value)}
                className="h-9 w-40 pl-8 text-xs"
              />
            </div>
            <Select
              value={levelFilter}
              onChange={(e) =>
                setLevelFilter(
                  (e.target as HTMLSelectElement).value as Level | "ALL",
                )
              }
              className="h-9 w-28 text-xs"
            >
              <option value="ALL">All levels</option>
              <option value="DEBUG">DEBUG</option>
              <option value="INFO">INFO</option>
              <option value="WARN">WARN</option>
              <option value="ERROR">ERROR</option>
            </Select>
            <Select
              value={String(timeFilter)}
              onChange={(e) =>
                setTimeFilter(Number((e.target as HTMLSelectElement).value))
              }
              className="h-9 w-28 text-xs"
            >
              {TIME_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </Select>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={() => setPaused((p) => !p)}
          >
            {paused ? "Resume" : "Pause"}
          </Button>
          <Button variant="outline" size="sm" onClick={() => setLines([])}>
            Clear
          </Button>
        </div>
      </div>

      <div className="flex-1 overflow-hidden rounded-xl border border-border shadow-sm">
        <div className="flex items-center gap-2 bg-zinc-800 px-4 py-2.5">
          <div className="flex gap-1.5">
            <span className="size-3 rounded-full bg-red-500" />
            <span className="size-3 rounded-full bg-yellow-400" />
            <span className="size-3 rounded-full bg-green-500" />
          </div>
          <span className="mx-auto font-mono text-xs text-zinc-400">
            magistrala-agent — logs
          </span>
          <span className="text-xs text-zinc-500">
            {filtered.length}
            {filtered.length !== lines.length && ` / ${lines.length}`} lines
          </span>
        </div>

        <div className="h-[calc(100vh-260px)] overflow-y-auto bg-zinc-900 p-4 font-mono text-xs leading-relaxed">
          {filtered.length === 0 ? (
            <p className="text-zinc-500">
              {lines.length === 0
                ? connected
                  ? "Waiting for log entries…"
                  : "Connecting to log stream…"
                : "No logs match the current filter."}
            </p>
          ) : (
            filtered.map((line, i) => {
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

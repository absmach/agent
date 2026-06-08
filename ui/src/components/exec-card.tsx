// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import { useEffect, useRef, useState } from "preact/hooks";

interface HistoryEntry {
  cmd: string;
  output: string;
  error?: boolean;
}

function parseCommand(input: string): string {
  const args: string[] = [];
  let current = "";
  let inQuote = false;
  let quoteChar = "";

  for (const char of input.trim()) {
    if (inQuote) {
      if (char === quoteChar) {
        inQuote = false;
      } else {
        current += char;
      }
    } else if (char === '"' || char === "'") {
      inQuote = true;
      quoteChar = char;
    } else if (char === " ") {
      if (current) {
        args.push(current);
        current = "";
      }
    } else {
      current += char;
    }
  }
  if (current) args.push(current);
  return args.join(",");
}

export function ExecCard() {
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [cmd, setCmd] = useState("");
  const [cmdHistory, setCmdHistory] = useState<string[]>([]);
  const [historyIdx, setHistoryIdx] = useState(-1);
  const [loading, setLoading] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (history.length === 0) return;
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [history, loading]);

  async function run() {
    const trimmed = cmd.trim();
    if (!trimmed || loading) return;

    setCmdHistory((prev) => [trimmed, ...prev]);
    setHistoryIdx(-1);
    setCmd("");
    setLoading(true);

    try {
      const res = await fetch("/exec", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          bn: "exec:",
          n: "exec",
          vs: parseCommand(trimmed),
        }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setHistory((prev) => [
        ...prev,
        { cmd: trimmed, output: data.vs ?? JSON.stringify(data, null, 2) },
      ]);
    } catch (err) {
      setHistory((prev) => [
        ...prev,
        { cmd: trimmed, output: String(err), error: true },
      ]);
    } finally {
      setLoading(false);
    }
  }

  function handleKeyDown(e: KeyboardEvent) {
    if (e.key === "Enter") {
      run();
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      const next = Math.min(historyIdx + 1, cmdHistory.length - 1);
      setHistoryIdx(next);
      setCmd(cmdHistory[next] ?? "");
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      const next = Math.max(historyIdx - 1, -1);
      setHistoryIdx(next);
      setCmd(next === -1 ? "" : (cmdHistory[next] ?? ""));
    }
  }

  return (
    <div className="overflow-hidden rounded-xl border shadow-sm">
      {/* Terminal title bar */}
      <div className="flex items-center gap-2 bg-zinc-800 px-4 py-2.5">
        <div className="flex gap-1.5">
          <span className="h-3 w-3 rounded-full bg-red-500" />
          <span className="h-3 w-3 rounded-full bg-yellow-400" />
          <span className="h-3 w-3 rounded-full bg-green-500" />
        </div>
        <span className="mx-auto font-mono text-xs text-zinc-400">
          magistrala-agent — bash
        </span>
        {history.length > 0 && (
          <button
            type="button"
            onClick={() => setHistory([])}
            className="text-xs text-zinc-500 hover:text-zinc-300 transition-colors"
          >
            Clear
          </button>
        )}
      </div>

      {/* biome-ignore lint/a11y/useSemanticElements: <button> can't wrap <input> per HTML spec */}
      <div
        role="button"
        tabIndex={0}
        className="min-h-72 max-h-112 w-full overflow-y-auto bg-zinc-900 p-4 font-mono text-sm text-left focus:outline-none focus:ring-2 focus:ring-inset focus:ring-zinc-500"
        onClick={() => inputRef.current?.focus()}
        onKeyDown={(e: KeyboardEvent) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            inputRef.current?.focus();
          }
        }}
      >
        {history.length === 0 && !loading && (
          <p className="text-zinc-500 text-xs">
            Type a command and press{" "}
            <kbd className="rounded border border-zinc-600 px-1 text-zinc-400">
              Enter
            </kbd>{" "}
            to run it. Use{" "}
            <kbd className="rounded border border-zinc-600 px-1 text-zinc-400">
              ↑
            </kbd>{" "}
            /{" "}
            <kbd className="rounded border border-zinc-600 px-1 text-zinc-400">
              ↓
            </kbd>{" "}
            to browse history.
          </p>
        )}

        {history.map((entry, i) => (
          <div key={i} className="mb-3">
            <div className="flex items-center gap-2">
              <span className="text-green-400 select-none">$</span>
              <span className="text-zinc-100">{entry.cmd}</span>
            </div>
            {entry.output && (
              <pre
                className={`mt-1 whitespace-pre-wrap break-all text-xs leading-relaxed ${
                  entry.error ? "text-red-400" : "text-zinc-300"
                }`}
              >
                {entry.output}
              </pre>
            )}
          </div>
        ))}

        <div className="flex items-center gap-2">
          <span className="text-green-400 select-none shrink-0">$</span>
          <input
            ref={inputRef}
            type="text"
            value={cmd}
            onInput={(e) => setCmd((e.target as HTMLInputElement).value)}
            onKeyDown={handleKeyDown}
            className={`min-w-0 flex-1 bg-transparent outline-none caret-green-400 placeholder:text-zinc-600 ${loading ? "animate-pulse text-zinc-500" : "text-zinc-100"}`}
            placeholder={loading ? "Running…" : "enter command…"}
            autofocus
            spellcheck={false}
            autocomplete="off"
          />
        </div>

        <div ref={bottomRef} />
      </div>
    </div>
  );
}

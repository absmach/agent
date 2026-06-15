// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import { Terminal, X } from "lucide-react";
import { useEffect, useRef, useState } from "preact/hooks";
import { ErrorAlert } from "@/components/error-alert";
import { PageHeader } from "@/components/page-header";
import { StatusBadge } from "@/components/status-badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";

export function TerminalPage() {
  const [connected, setConnected] = useState(false);
  const [lines, setLines] = useState<string[]>([
    "/ # Welcome to the interactive terminal. Type a command and press Enter.",
  ]);
  const [input, setInput] = useState("");
  const [error, setError] = useState("");
  const bottomRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [lines]);

  function connect() {
    setError("");
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const url = `${protocol}//${window.location.host}/terminal/ws`;

    try {
      const socket = new WebSocket(url);

      socket.onopen = () => {
        setConnected(true);
        setLines((prev) => [...prev, "/ # Connected to terminal session."]);
        wsRef.current = socket;
      };

      socket.onmessage = (e) => {
        if (e.data instanceof Blob) {
          const reader = new FileReader();
          reader.onload = () => {
            const text = reader.result as string;
            setLines((prev) => [...prev.slice(-499), text]);
          };
          reader.readAsText(e.data);
        } else {
          setLines((prev) => [...prev.slice(-499), e.data as string]);
        }
      };

      socket.onerror = () => {
        setError("WebSocket connection error");
        setConnected(false);
      };

      socket.onclose = () => {
        setConnected(false);
        setLines((prev) => [...prev, "/ # Connection closed."]);
        wsRef.current = null;
      };
    } catch (e) {
      setError(String(e));
    }
  }

  function disconnect() {
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
      setConnected(false);
    }
  }

  function sendCommand() {
    const trimmed = input.trim();
    if (
      !trimmed ||
      !wsRef.current ||
      wsRef.current.readyState !== WebSocket.OPEN
    )
      return;

    setLines((prev) => [...prev, `$ ${trimmed}`]);
    wsRef.current.send(`${trimmed}\n`);
    setInput("");
  }

  function handleKeyDown(e: KeyboardEvent) {
    if (e.key === "Enter") {
      sendCommand();
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Terminal"
        subtitle="Interactive shell session via WebSocket."
        actions={
          <div className="flex items-center gap-2">
            {connected ? (
              <>
                <StatusBadge status="online" label="Connected" />
                <Button variant="outline" size="sm" onClick={disconnect}>
                  <X className="size-3" />
                  Disconnect
                </Button>
              </>
            ) : (
              <>
                <StatusBadge status="offline" label="Disconnected" />
                <Button size="sm" onClick={connect}>
                  <Terminal className="size-3" />
                  Connect
                </Button>
              </>
            )}
          </div>
        }
      />

      <ErrorAlert error={error} />

      <Card>
        <div>
          <div className="flex items-center gap-2 bg-zinc-800 px-4 py-2.5">
            <div className="flex gap-1.5">
              <span className="size-3 rounded-full bg-red-500" />
              <span className="size-3 rounded-full bg-yellow-400" />
              <span className="size-3 rounded-full bg-green-500" />
            </div>
            <span className="mx-auto font-mono text-xs text-zinc-400">
              magistrala-agent — interactive shell
            </span>
            {lines.length > 0 && (
              <button
                type="button"
                onClick={() => setLines([])}
                className="text-xs text-zinc-500 transition-colors hover:text-zinc-300"
              >
                Clear
              </button>
            )}
          </div>

          {/* biome-ignore lint/a11y/useSemanticElements: need click-to-focus on container */}
          <div
            role="button"
            tabIndex={0}
            className="min-h-72 max-h-112 w-full overflow-y-auto bg-zinc-900 p-4 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-inset focus:ring-zinc-500"
            onClick={() => inputRef.current?.focus()}
            onKeyDown={(e: KeyboardEvent) => {
              if (e.target !== e.currentTarget) return;
              if (e.key === "Enter") {
                e.preventDefault();
                inputRef.current?.focus();
              }
            }}
          >
            {lines.map((line, i) => (
              <div
                key={i}
                className="whitespace-pre-wrap break-all text-zinc-300"
              >
                {line}
              </div>
            ))}
            <div className="mb-2" ref={bottomRef} />
            {connected && (
              <div className="flex items-center gap-2">
                <span className="select-none text-green-400">$</span>
                <input
                  ref={inputRef}
                  type="text"
                  value={input}
                  onInput={(e) =>
                    setInput((e.target as HTMLInputElement).value)
                  }
                  onKeyDown={handleKeyDown}
                  className="min-w-0 flex-1 bg-transparent text-zinc-100 outline-none caret-green-400 placeholder:text-zinc-600"
                  placeholder="enter command…"
                  spellcheck={false}
                  autocomplete="off"
                />
              </div>
            )}
            {!connected && (
              <p className="mt-8 text-center text-xs text-zinc-500">
                Click <strong>Connect</strong> to start an interactive terminal
                session.
              </p>
            )}
          </div>
        </div>
      </Card>
    </div>
  );
}

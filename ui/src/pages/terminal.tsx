// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import { WTerm } from "@wterm/dom";
import "@wterm/dom/css";
import { Terminal, X } from "lucide-react";
import { useEffect, useRef, useState } from "preact/hooks";
import { ErrorAlert } from "@/components/error-alert";
import { PageHeader } from "@/components/page-header";
import { StatusBadge } from "@/components/status-badge";
import { Button } from "@/components/ui/button";

export function TerminalPage() {
  const containerRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<WTerm | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let destroyed = false;

    async function init() {
      if (!containerRef.current) return;

      const term = new WTerm(containerRef.current, {
        cols: 80,
        rows: 24,
        cursorBlink: true,
        onData: (data) => {
          if (wsRef.current?.readyState === WebSocket.OPEN) {
            wsRef.current.send(data);
          }
        },
        onResize: (cols, rows) => {
          if (wsRef.current?.readyState === WebSocket.OPEN) {
            wsRef.current.send(
              JSON.stringify({ type: "resize", columns: cols, rows }),
            );
          }
        },
      });

      await term.init();

      if (destroyed) {
        term.destroy();
        return;
      }

      termRef.current = term;
      setLoading(false);
      connect();
    }

    init();

    return () => {
      destroyed = true;
      wsRef.current?.close();
      wsRef.current = null;
      termRef.current?.destroy();
      termRef.current = null;
    };
  }, []);

  function connect() {
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    setError("");
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const url = `${protocol}//${window.location.host}/terminal/ws`;
    const socket = new WebSocket(url);
    socket.binaryType = "arraybuffer";

    socket.onopen = () => {
      setConnected(true);
      const term = termRef.current;
      if (term) {
        socket.send(
          JSON.stringify({
            type: "resize",
            columns: term.cols,
            rows: term.rows,
          }),
        );
      }
      termRef.current?.focus();
    };

    socket.onmessage = (e) => {
      const data = typeof e.data === "string" ? e.data : new Uint8Array(e.data);
      termRef.current?.write(data);
    };

    socket.onerror = () => setError("WebSocket connection error");

    socket.onclose = () => {
      setConnected(false);
      wsRef.current = null;
    };

    wsRef.current = socket;
  }

  function disconnect() {
    wsRef.current?.close();
    wsRef.current = null;
    setConnected(false);
  }

  return (
    <div className="flex h-full flex-col gap-4 p-4 sm:p-6">
      <PageHeader
        title="Terminal"
        subtitle="Interactive shell session on the agent device."
        actions={
          <div className="flex items-center gap-2">
            <StatusBadge
              status={connected ? "online" : "offline"}
              label={connected ? "Connected" : "Disconnected"}
              pulse={connected}
            />
            {connected ? (
              <Button variant="outline" size="sm" onClick={disconnect}>
                <X className="size-3" />
                Disconnect
              </Button>
            ) : (
              <Button size="sm" onClick={connect} disabled={loading}>
                <Terminal className="size-3" />
                {loading ? "Loading…" : "Connect"}
              </Button>
            )}
          </div>
        }
      />

      <ErrorAlert error={error} />

      <div className="flex-1 overflow-hidden rounded-xl border border-border shadow-sm">
        <div className="flex items-center gap-2 bg-zinc-800 px-4 py-2.5">
          <div className="flex gap-1.5">
            <span className="size-3 rounded-full bg-red-500" />
            <span className="size-3 rounded-full bg-yellow-400" />
            <span className="size-3 rounded-full bg-green-500" />
          </div>
          <span className="mx-auto font-mono text-xs text-zinc-400">
            magistrala-agent — shell
          </span>
        </div>
        <div
          ref={containerRef}
          className="h-[calc(100vh-240px)] w-full"
          style={{
            borderRadius: 0,
            boxShadow: "none",
            padding: "8px",
          }}
        />
      </div>
    </div>
  );
}

import { AlertCircle, Terminal, Wifi, WifiOff, X } from "lucide-react";
import { useEffect, useRef, useState } from "preact/hooks";
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
    <div className="space-y-[22px]">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-[1.35rem] font-bold leading-tight tracking-tight">
            Terminal
          </h1>
          <p className="mt-1 text-[0.825rem] text-muted-foreground">
            Interactive shell session via WebSocket.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {connected ? (
            <>
              <span className="flex items-center gap-1.5 rounded-full bg-emerald-500/15 px-2.5 py-1 text-[0.7rem] font-semibold text-emerald-300">
                <Wifi className="h-3 w-3" />
                Connected
              </span>
              <Button variant="outline" size="sm" onClick={disconnect}>
                <X className="h-3 w-3" />
                Disconnect
              </Button>
            </>
          ) : (
            <>
              <span className="flex items-center gap-1.5 rounded-full bg-zinc-500/15 px-2.5 py-1 text-[0.7rem] font-semibold text-zinc-400">
                <WifiOff className="h-3 w-3" />
                Disconnected
              </span>
              <Button size="sm" onClick={connect}>
                <Terminal className="h-3 w-3" />
                Connect
              </Button>
            </>
          )}
        </div>
      </div>

      {error && (
        <div className="flex items-center gap-2 rounded-lg border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">
          <AlertCircle className="h-4 w-4 shrink-0" />
          {error}
        </div>
      )}

      <Card>
        <div>
          <div className="flex items-center gap-2 bg-zinc-800 px-4 py-2.5">
            <div className="flex gap-1.5">
              <span className="h-3 w-3 rounded-full bg-red-500" />
              <span className="h-3 w-3 rounded-full bg-yellow-400" />
              <span className="h-3 w-3 rounded-full bg-green-500" />
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
                <span className="text-green-400 select-none">$</span>
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

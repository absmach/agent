// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import { useEffect, useState } from "preact/hooks";

export type LinkStatus = "checking" | "online" | "offline";

/** Polls the agent's /config endpoint to track local link liveness. */
export function useAgentStatus(intervalMs = 5000): LinkStatus {
  const [status, setStatus] = useState<LinkStatus>("checking");

  useEffect(() => {
    let alive = true;
    async function check() {
      try {
        const res = await fetch("/config", {
          cache: "no-store",
          signal: AbortSignal.timeout(3000),
        });
        if (alive) setStatus(res.ok ? "online" : "offline");
      } catch {
        if (alive) setStatus("offline");
      }
    }
    check();
    const id = setInterval(check, intervalMs);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [intervalMs]);

  return status;
}

export interface AgentInfo {
  status?: string;
  version?: string;
  commit?: string;
  instance_id?: string;
  build_time?: string;
}

/** Fetches static agent identity from /health (best effort). */
export function useAgentInfo(): AgentInfo | null {
  const [info, setInfo] = useState<AgentInfo | null>(null);
  useEffect(() => {
    let alive = true;
    fetch("/health", { cache: "no-store", signal: AbortSignal.timeout(3000) })
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => alive && d && setInfo(d))
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, []);
  return info;
}

export function useTheme() {
  const [dark, setDark] = useState(false);

  useEffect(() => {
    const saved = localStorage.getItem("agent-ui-theme");
    const useDark =
      saved === "dark" ||
      (!saved && window.matchMedia("(prefers-color-scheme: dark)").matches);
    apply(useDark);
    setDark(useDark);
  }, []);

  function apply(value: boolean) {
    document.documentElement.classList.toggle("dark", value);
    document.documentElement.dataset.theme = value ? "dark" : "light";
  }

  function toggle() {
    setDark((prev) => {
      const next = !prev;
      localStorage.setItem("agent-ui-theme", next ? "dark" : "light");
      apply(next);
      return next;
    });
  }

  return { dark, toggle };
}

/** Polls /devices and returns total + active counts (null until first load). */
export function useDeviceCount(intervalMs = 15000) {
  const [count, setCount] = useState<number | null>(null);
  const [online, setOnline] = useState(0);
  useEffect(() => {
    let alive = true;
    async function load() {
      try {
        const res = await fetch("/devices", {
          cache: "no-store",
          signal: AbortSignal.timeout(3000),
        });
        if (!res.ok) return;
        const data = await res.json();
        const list: { active?: boolean }[] = data.devices ?? [];
        if (!alive) return;
        setCount(list.length);
        setOnline(list.filter((d) => d.active).length);
      } catch {
        /* offline; keep previous value */
      }
    }
    load();
    const id = setInterval(load, intervalMs);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [intervalMs]);
  return { count, online };
}

/** A 1Hz ticking clock. */
export function useClock() {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(id);
  }, []);
  return now;
}

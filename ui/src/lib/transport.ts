// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

type RuntimeConfig = { gatewayUrl?: string; agentId?: string; token?: string };
type JSONRecord = Record<string, unknown>;
type HealthResult = {
  healthy?: boolean;
  status?: string;
  version?: string;
  commit?: string;
  description?: string;
  build_time?: string;
  instance_id?: string;
};
type SnapshotResult = {
  config?: unknown;
  telemetry?: unknown;
  revision?: number;
};
type Job = {
  id: string;
  state: "queued" | "running" | "waiting" | "succeeded" | "failed" | "cancelled";
  result?: unknown;
  error?: string;
};

declare global {
  interface Window {
    __AGENT_UI_CONFIG__?: RuntimeConfig;
  }
}

const config = window.__AGENT_UI_CONFIG__ ?? {};
const nativeFetch = globalThis.fetch.bind(globalThis);
export const remoteMode = Boolean(config.gatewayUrl && config.agentId);

function gatewayToken(): string {
  return config.token || localStorage.getItem("agent-gateway-token") || "";
}

function agentID(): string {
  return config.agentId || localStorage.getItem("agent-gateway-agent") || "";
}

export function gatewayWS(
  path: "events" | "logs" | "terminal",
): { url: string; protocols: string[] } | null {
  if (!remoteMode) return null;
  const base = (config.gatewayUrl ?? "")
    .replace(/^http/, "ws")
    .replace(/\/$/, "");
  const encoded = btoa(gatewayToken())
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return {
    url: `${base}/api/agents/${encodeURIComponent(agentID())}/${path}`,
    protocols: [`bearer.${encoded}`],
  };
}

async function rpc(method: string, params: unknown = {}): Promise<unknown> {
  const base = (config.gatewayUrl ?? "").replace(/\/$/, "");
  const response = await nativeFetch(
    `${base}/api/agents/${encodeURIComponent(agentID())}/rpc`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${gatewayToken()}`,
      },
      body: JSON.stringify({ method, params }),
    },
  );
  const envelope = await response.json();
  if (!response.ok || envelope.error)
    throw new Error(envelope.error || `HTTP ${response.status}`);
  return envelope.value ?? null;
}

async function waitJob(started: unknown, timeoutMs = 120_000): Promise<unknown> {
  const initial = started as Job;
  if (!initial?.id) throw new Error("Agent returned an invalid job");
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const job = (await rpc("job.get", { jobId: initial.id })) as Job;
    switch (job.state) {
      case "succeeded":
        return job.result;
      case "failed":
      case "cancelled":
        throw new Error(job.error || `Job ${job.state}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 300));
  }
  throw new Error("Job did not finish before the UI timeout");
}

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

async function body(init?: RequestInit): Promise<JSONRecord> {
  if (!init?.body || typeof init.body !== "string") return {};
  return JSON.parse(init.body);
}

function hexToBase64(hex: string): string {
  if (hex.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(hex))
    throw new Error("Device data must be hexadecimal");
  let binary = "";
  for (let index = 0; index < hex.length; index += 2)
    binary += String.fromCharCode(Number.parseInt(hex.slice(index, index + 2), 16));
  return btoa(binary);
}

function base64ToHex(value: string): string {
  return Array.from(atob(value), (char) =>
    char.charCodeAt(0).toString(16).padStart(2, "0"),
  ).join("");
}

function decodeFlow(value: unknown): unknown {
  if (typeof value !== "string" || value === "") return value;
  try {
    return JSON.parse(decodeURIComponent(escape(atob(value))));
  } catch {
    return value;
  }
}

export async function agentFetch(
  input: RequestInfo | URL,
  init?: RequestInit,
): Promise<Response> {
  if (!remoteMode || typeof input !== "string" || !input.startsWith("/"))
    return nativeFetch(input, init);

  const url = new URL(input, location.origin);
  const path = url.pathname;
  const method = (init?.method || "GET").toUpperCase();
  try {
    if (path === "/health") {
      const result = (await rpc("system.health.get")) as HealthResult;
      return json({
        ...result,
        status: result.status ?? (result.healthy ? "pass" : "fail"),
      });
    }
    if (path === "/config" && method === "GET") {
      const result = (await rpc("system.snapshot.get")) as SnapshotResult;
      return json(result.config);
    }
    if (path === "/config" && method === "POST") {
      const patch = await body(init);
      const current = (await rpc("config.get")) as JSONRecord;
      const merged = {
        ...current,
        ...patch,
        server: { ...(current.server as JSONRecord), ...(patch.server as JSONRecord) },
        channels: {
          ...(current.channels as JSONRecord),
          ...(patch.channels as JSONRecord),
        },
        nodered: {
          ...(current.nodered as JSONRecord),
          ...(patch.nodered as JSONRecord),
        },
        log: { ...(current.log as JSONRecord), ...(patch.log as JSONRecord) },
        mqtt: { ...(current.mqtt as JSONRecord), ...(patch.mqtt as JSONRecord) },
        coap: { ...(current.coap as JSONRecord), ...(patch.coap as JSONRecord) },
      };
      return json(
        await waitJob(
          await rpc("config.apply", {
            config: merged,
          }),
        ),
      );
    }
    if (path === "/telemetry/data") {
      const result = (await rpc("system.snapshot.get")) as SnapshotResult;
      return json(result.telemetry);
    }
    if (path === "/services" && method === "GET")
      return json(await rpc("service.list"));
    if (path === "/services" && method === "POST")
      return json(await rpc("service.register", await body(init)));
    if (path.startsWith("/services/") && method === "DELETE")
      return json(
        await rpc("service.remove", {
          name: decodeURIComponent(path.slice(10)),
        }),
      );

    if (path === "/devices" && method === "GET")
      return json({ devices: await rpc("device.list") });
    if (path === "/devices" && method === "POST") {
      const params = await body(init);
      return json(
        await rpc("device.register", {
          name: params.name,
          externalId: params.ext_id,
          externalKey: params.ext_key,
          interfaceType: params.interface_type,
          interfaceAddress: params.interface_addr,
        }),
        201,
      );
    }
    if (path === "/devices/backup")
      return json(await waitJob(await rpc("backup.create")));
    if (path === "/devices/restore" && method === "POST") {
      const result = (await waitJob(
        await rpc("backup.restore", {
          backup: await body(init),
          replace: url.searchParams.get("replace") === "true",
        }),
      )) as { imported?: number };
      return json({ imported: result?.imported ?? 0 });
    }

    const device = path.match(
      /^\/devices\/([^/]+)(?:\/(seen|open|close|read|write))?$/,
    );
    if (device) {
      const deviceId = decodeURIComponent(device[1]);
      const action = device[2];
      if (!action && method === "GET")
        return json(await rpc("device.get", { deviceId }));
      if (!action && method === "DELETE")
        return json(await rpc("device.remove", { deviceId }));
      if (action === "seen")
        return json(await rpc("device.markSeen", { deviceId }));
      if (action === "open" || action === "close")
        return json(await rpc(`device.interface.${action}`, { deviceId }));
      if (action === "read") {
        const params = await body(init);
        const result = (await rpc("device.interface.read", {
          deviceId,
          bytes: Number(params.bytes) || 1024,
        })) as { dataBase64?: string };
        return json({
          data: result.dataBase64 ? base64ToHex(result.dataBase64) : "",
        });
      }
      if (action === "write") {
        const params = await body(init);
        const result = (await rpc("device.interface.write", {
          deviceId,
          dataBase64: hexToBase64(String(params.data ?? "")),
        })) as { bytesWritten?: number };
        return json({ written: result.bytesWritten ?? 0 });
      }
    }

    if (path === "/nodered" && method === "POST") {
      const params = await body(init);
      const command = String(params.command ?? "");
      if (command === "nodered-ping")
        return json({
          response: await rpc("nodeRed.action.execute", { action: "ping" }),
        });
      if (command === "nodered-state")
        return json({ response: await rpc("nodeRed.status.get") });
      if (command === "nodered-flows")
        return json({
          response: JSON.stringify(await rpc("nodeRed.flows.get")),
        });
      if (command === "nodered-deploy")
        return json({
          response: await waitJob(
            await rpc("nodeRed.flows.deploy", {
              flows: decodeFlow(params.flows),
            }),
          ),
        });
      if (command === "nodered-add-flow")
        return json({
          response: await rpc("nodeRed.action.execute", {
            action: "addFlow",
            flows: decodeFlow(params.flows),
          }),
        });
    }

    if (path === "/ota/status")
      return json(await rpc("firmware.update.status.get"));
    if (path === "/ota/abort")
      return json({ status: await rpc("firmware.update.abort") });
    if (path === "/ota" && method === "POST")
      return json(
        { status: await rpc("firmware.update.start", await body(init)) },
        202,
      );
    if (path === "/ota/data" && method === "POST")
      return json(
        {
          error:
            "Direct MQTT firmware upload was removed. Upload the artifact over HTTPS and submit its URL.",
        },
        410,
      );

    if (path === "/control" && method === "POST") {
      const params = await body(init);
      const actions: Record<string, string> = {
        stop: "agent.pause",
        start: "agent.resume",
        reload: "agent.reload",
      };
      const rpcMethod = actions[String(params.command ?? "")];
      if (!rpcMethod) return json({ error: "Unknown control action" }, 400);
      return json({ response: await rpc(rpcMethod) }, 202);
    }
    if (path === "/reset" && method === "POST")
      return json(
        { status: await rpc("agent.reset", await body(init)) },
        202,
      );

    if (path === "/config/runtime" && method === "POST") {
      const params = await body(init);
      return json({ value: await rpc("runtimeConfig.set", params) });
    }
    if (path === "/config/runtime") {
      const result = (await rpc("runtimeConfig.list")) as {
        config?: Record<string, string>;
        revision?: number;
      };
      return json(result);
    }

    return json(
      { error: `Remote operation is not available: ${method} ${path}` },
      501,
    );
  } catch (error) {
    return json({ error: String(error) }, 502);
  }
}

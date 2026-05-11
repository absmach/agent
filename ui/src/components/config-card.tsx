// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import { CheckCircle, Settings, XCircle } from "lucide-react";
import { useCallback, useEffect, useState } from "preact/hooks";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select } from "@/components/ui/select";

interface Config {
  httpPort: string;
  clientID: string;
  clientKey: string;
  channelID: string;
  logLevel: string;
  mqttURL: string;
  nodeRedURL: string;
  brokerURL: string;
}

const emptyConfig: Config = {
  httpPort: "",
  clientID: "",
  clientKey: "",
  channelID: "",
  logLevel: "info",
  mqttURL: "",
  nodeRedURL: "",
  brokerURL: "",
};

type Status = { ok: boolean; message: string } | null;

export function ConfigCard() {
  const [config, setConfig] = useState<Config>(emptyConfig);
  const [status, setStatus] = useState<Status>(null);
  const [loading, setLoading] = useState(false);

  const fetchConfig = useCallback(async () => {
    setLoading(true);
    setStatus(null);
    try {
      const res = await fetch("/config");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setConfig({
        httpPort: data.server?.port ?? "",
        clientID: data.mqtt?.username ?? "",
        clientKey: data.mqtt?.password ?? "",
        channelID: data.channels?.id ?? "",
        logLevel: data.log?.level ?? "info",
        mqttURL: data.mqtt?.url ?? "",
        nodeRedURL: data.nodered?.url ?? "",
        brokerURL: data.server?.broker_url ?? "",
      });
      setStatus({ ok: true, message: "Config loaded" });
    } catch (err) {
      setStatus({ ok: false, message: String(err) });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchConfig();
  }, [fetchConfig]);

  async function saveConfig() {
    setLoading(true);
    setStatus(null);
    try {
      const body = {
        server: { port: config.httpPort, broker_url: config.brokerURL },
        channels: { id: config.channelID },
        mqtt: {
          url: config.mqttURL,
          username: config.clientID,
          password: config.clientKey,
        },
        nodered: { url: config.nodeRedURL },
        log: { level: config.logLevel },
      };
      const res = await fetch("/config", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setStatus({ ok: true, message: "Config saved successfully" });
    } catch (err) {
      setStatus({ ok: false, message: String(err) });
    } finally {
      setLoading(false);
    }
  }

  function field(
    id: keyof Config,
    label: string,
    placeholder: string,
    type = "text",
  ) {
    return (
      <div className="space-y-1.5">
        <Label htmlFor={id}>{label}</Label>
        <Input
          id={id}
          type={type}
          placeholder={placeholder}
          value={config[id]}
          onInput={(e) =>
            setConfig((c) => ({
              ...c,
              [id]: (e.target as HTMLInputElement).value,
            }))
          }
        />
      </div>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <Settings className="h-4 w-4" />
          Configuration
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {field("httpPort", "HTTP Port", "Agent HTTP API port")}
        {field("clientID", "Client ID", "Magistrala client ID (MQTT username)")}
        {field(
          "clientKey",
          "Client Key",
          "Magistrala client secret (MQTT password)",
          "password",
        )}
        {field("channelID", "Channel ID", "Magistrala channel ID")}
        {field("mqttURL", "MQTT URL", "Magistrala MQTT broker URL")}
        {field("nodeRedURL", "Node-RED URL", "Node-RED API URL")}
        {field("brokerURL", "Broker URL", "Internal FluxMQ AMQP broker URL")}

        <div className="space-y-1.5">
          <Label htmlFor="logLevel">Log Level</Label>
          <Select
            id="logLevel"
            value={config.logLevel}
            onChange={(e) =>
              setConfig((c) => ({
                ...c,
                logLevel: (e.target as HTMLSelectElement).value,
              }))
            }
          >
            {["debug", "info", "warn", "error"].map((l) => (
              <option key={l} value={l}>
                {l}
              </option>
            ))}
          </Select>
        </div>

        <div className="flex gap-2 pt-1">
          <Button variant="outline" onClick={fetchConfig} disabled={loading}>
            Get Config
          </Button>
          <Button onClick={saveConfig} disabled={loading}>
            Save Config
          </Button>
        </div>

        {status && (
          <div
            className={`flex items-center gap-2 rounded-md px-3 py-2 text-sm ${
              status.ok
                ? "bg-success/10 text-success border border-success/20"
                : "bg-destructive/10 text-destructive border border-destructive/20"
            }`}
          >
            {status.ok ? (
              <CheckCircle className="h-4 w-4 shrink-0" />
            ) : (
              <XCircle className="h-4 w-4 shrink-0" />
            )}
            {status.message}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

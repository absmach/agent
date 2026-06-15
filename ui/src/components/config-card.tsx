// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import {
  Check,
  CheckCircle,
  Copy,
  Eye,
  EyeOff,
  Settings,
  XCircle,
} from "lucide-react";
import { useCallback, useEffect, useState } from "preact/hooks";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select } from "@/components/ui/select";
import { useToast } from "@/components/ui/toaster";

interface Config {
  httpPort: string;
  clientID: string;
  clientKey: string;
  ctrlChannelID: string;
  dataChannelID: string;
  logLevel: string;
  mqttURL: string;
  nodeRedURL: string;
}

const emptyConfig: Config = {
  httpPort: "",
  clientID: "",
  clientKey: "",
  ctrlChannelID: "",
  dataChannelID: "",
  logLevel: "info",
  mqttURL: "",
  nodeRedURL: "",
};

type Status = { ok: boolean; message: string } | null;

function SecretField({
  id,
  label,
  placeholder,
  value,
  onInput,
}: {
  id: string;
  label: string;
  placeholder: string;
  value: string;
  onInput: (e: Event) => void;
}) {
  const { toast } = useToast();
  const [visible, setVisible] = useState(false);
  const [copied, setCopied] = useState(false);

  async function copy() {
    await navigator.clipboard.writeText(value);
    setCopied(true);
    toast({ message: "Copied to clipboard", variant: "success" });
    setTimeout(() => setCopied(false), 1500);
  }

  return (
    <div className="flex flex-col gap-1.5">
      <Label htmlFor={id}>{label}</Label>
      <div className="relative flex items-center">
        <Input
          id={id}
          type={visible ? "text" : "password"}
          placeholder={placeholder}
          value={value}
          className="pr-16"
          onInput={onInput}
        />
        <div className="absolute right-1 flex items-center gap-0.5">
          <button
            type="button"
            onClick={() => setVisible((v) => !v)}
            className="rounded p-1.5 text-muted-foreground transition-colors hover:text-foreground"
            title={visible ? "Hide" : "Show"}
          >
            {visible ? (
              <EyeOff className="size-3.5" />
            ) : (
              <Eye className="size-3.5" />
            )}
          </button>
          <button
            type="button"
            onClick={copy}
            className="rounded p-1.5 text-muted-foreground transition-colors hover:text-foreground"
            title="Copy to clipboard"
          >
            {copied ? (
              <Check className="size-3.5 text-success" />
            ) : (
              <Copy className="size-3.5" />
            )}
          </button>
        </div>
      </div>
    </div>
  );
}

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
        ctrlChannelID: data.channels?.ctrl_id ?? "",
        dataChannelID: data.channels?.data_id ?? "",
        logLevel: data.log?.level ?? "info",
        mqttURL: data.mqtt?.url ?? "",
        nodeRedURL: data.nodered?.url ?? "",
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
        server: { port: config.httpPort },
        channels: {
          ctrl_id: config.ctrlChannelID,
          data_id: config.dataChannelID,
        },
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
      <div className="flex flex-col gap-1.5">
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
          <Settings className="size-4" />
          Configuration
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid gap-4 sm:grid-cols-2">
          {field("httpPort", "HTTP Port", "Agent HTTP API port")}
          {field(
            "clientID",
            "Client ID",
            "Magistrala client ID (MQTT username)",
          )}
          <SecretField
            id="clientKey"
            label="Client Key"
            placeholder="Magistrala client secret (MQTT password)"
            value={config.clientKey}
            onInput={(e) =>
              setConfig((c) => ({
                ...c,
                clientKey: (e.target as HTMLInputElement).value,
              }))
            }
          />
          {field(
            "ctrlChannelID",
            "Control Channel ID",
            "Magistrala control channel ID",
          )}
          {field(
            "dataChannelID",
            "Data Channel ID",
            "Magistrala data channel ID",
          )}
          {field("mqttURL", "MQTT URL", "Magistrala MQTT broker URL")}
          {field("nodeRedURL", "Node-RED URL", "Node-RED API URL")}
          <div className="flex flex-col gap-1.5">
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
          <div className="flex items-end gap-2 sm:col-span-2">
            <Button variant="outline" onClick={fetchConfig} disabled={loading}>
              Get Config
            </Button>
            <Button onClick={saveConfig} disabled={loading}>
              Save Config
            </Button>
          </div>
        </div>

        {status && (
          <div
            className={`mt-4 flex items-center gap-2 rounded-lg border px-4 py-3 text-sm ${
              status.ok
                ? "border-success/30 bg-success/10 text-success"
                : "border-destructive/30 bg-destructive/10 text-destructive"
            }`}
          >
            {status.ok ? (
              <CheckCircle className="size-4 shrink-0" />
            ) : (
              <XCircle className="size-4 shrink-0" />
            )}
            {status.message}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

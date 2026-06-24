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
  gatewayID: string;
  gatewayKey: string;
  ctrlChannelID: string;
  dataChannelID: string;
  logLevel: string;
  mqttURL: string;
  nodeRedURL: string;
  transport: string;
  coapURL: string;
  coapPSK: string;
  coapSkipTLSVer: boolean;
  coapMaxObserve: number;
  coapMaxRetransmits: number;
  coapKeepAlive: number;
  coapContentFormat: number;
  coapCert: string;
  coapKey: string;
  coapCA: string;
}

const emptyConfig: Config = {
  httpPort: "",
  gatewayID: "",
  gatewayKey: "",
  ctrlChannelID: "",
  dataChannelID: "",
  logLevel: "info",
  mqttURL: "",
  nodeRedURL: "",
  transport: "mqtt",
  coapURL: "",
  coapPSK: "",
  coapSkipTLSVer: false,
  coapMaxObserve: 0,
  coapMaxRetransmits: 0,
  coapKeepAlive: 0,
  coapContentFormat: 0,
  coapCert: "",
  coapKey: "",
  coapCA: "",
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
        gatewayID: data.mqtt?.username ?? "",
        gatewayKey: data.mqtt?.password ?? "",
        ctrlChannelID: data.channels?.ctrl_id ?? "",
        dataChannelID: data.channels?.data_id ?? "",
        logLevel: data.log?.level ?? "info",
        mqttURL: data.mqtt?.url ?? "",
        nodeRedURL: data.nodered?.url ?? "",
        transport: data.transport ?? "mqtt",
        coapURL: data.coap?.url ?? "",
        coapPSK: data.coap?.psk ?? "",
        coapSkipTLSVer: data.coap?.skip_tls_ver ?? false,
        coapMaxObserve: data.coap?.max_observe ?? 0,
        coapMaxRetransmits: data.coap?.max_retransmits ?? 0,
        coapKeepAlive: data.coap?.keep_alive ?? 0,
        coapContentFormat: data.coap?.content_format ?? 0,
        coapCert: data.coap?.cert ?? "",
        coapKey: data.coap?.key ?? "",
        coapCA: data.coap?.ca ?? "",
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

  function buildPayload() {
    const body: Record<string, unknown> = {
      server: { port: config.httpPort },
      channels: {
        ctrl_id: config.ctrlChannelID,
        data_id: config.dataChannelID,
      },
      nodered: { url: config.nodeRedURL },
      log: { level: config.logLevel },
      transport: config.transport,
    };
    if (config.transport === "coap") {
      body.coap = {
        url: config.coapURL,
        psk: config.coapPSK,
        skip_tls_ver: config.coapSkipTLSVer,
        max_observe: config.coapMaxObserve,
        max_retransmits: config.coapMaxRetransmits,
        keep_alive: config.coapKeepAlive,
        content_format: config.coapContentFormat,
        cert: config.coapCert,
        key: config.coapKey,
        ca: config.coapCA,
      };
    } else {
      body.mqtt = {
        url: config.mqttURL,
        username: config.gatewayID,
        password: config.gatewayKey,
      };
    }
    return body;
  }

  async function saveConfig() {
    setLoading(true);
    setStatus(null);
    try {
      const res = await fetch("/config", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(buildPayload()),
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
          value={String(config[id])}
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

  function numberField(id: keyof Config, label: string, placeholder: string) {
    return (
      <div className="flex flex-col gap-1.5">
        <Label htmlFor={id}>{label}</Label>
        <Input
          id={id}
          type="number"
          placeholder={placeholder}
          value={String(config[id])}
          onInput={(e) =>
            setConfig((c) => ({
              ...c,
              [id]: Number((e.target as HTMLInputElement).value),
            }))
          }
        />
      </div>
    );
  }

  const isCoap = config.transport === "coap";

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

          <div className="flex flex-col gap-1.5">
            <Label htmlFor="transport">Transport</Label>
            <Select
              id="transport"
              value={config.transport}
              onChange={(e) =>
                setConfig((c) => ({
                  ...c,
                  transport: (e.target as HTMLSelectElement).value,
                }))
              }
            >
              <option value="mqtt">MQTT</option>
              <option value="coap">CoAP</option>
            </Select>
          </div>

          {isCoap ? (
            <>
              {field("coapURL", "CoAP URL", "coaps://broker.example.com:5684")}
              <SecretField
                id="coapPSK"
                label="PSK Identity"
                placeholder="Pre-shared key identity"
                value={config.coapPSK}
                onInput={(e) =>
                  setConfig((c) => ({
                    ...c,
                    coapPSK: (e.target as HTMLInputElement).value,
                  }))
                }
              />
              {numberField(
                "coapKeepAlive",
                "Keep Alive (s)",
                "CoAP keep-alive interval in seconds",
              )}
              {numberField(
                "coapMaxObserve",
                "Max Observe",
                "Max concurrent observe relations",
              )}
              {numberField(
                "coapMaxRetransmits",
                "Max Retransmits",
                "Max retransmission attempts",
              )}
              {numberField(
                "coapContentFormat",
                "Content Format",
                "Content format ID (e.g. 110 for SenML+JSON)",
              )}
              {field("coapCert", "Gateway Cert", "TLS gateway certificate")}
              <SecretField
                id="coapKey"
                label="Gateway Key"
                placeholder="TLS gateway private key"
                value={config.coapKey}
                onInput={(e) =>
                  setConfig((c) => ({
                    ...c,
                    coapKey: (e.target as HTMLInputElement).value,
                  }))
                }
              />
              {field("coapCA", "CA Cert", "CA certificate for verification")}
            </>
          ) : (
            <>
              {field(
                "gatewayID",
                "Gateway ID",
                "Magistrala gateway ID (MQTT username)",
              )}
              <SecretField
                id="gatewayKey"
                label="Gateway Key"
                placeholder="Magistrala gateway secret (MQTT password)"
                value={config.gatewayKey}
                onInput={(e) =>
                  setConfig((c) => ({
                    ...c,
                    gatewayKey: (e.target as HTMLInputElement).value,
                  }))
                }
              />
              {field("mqttURL", "MQTT URL", "Magistrala MQTT broker URL")}
            </>
          )}

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

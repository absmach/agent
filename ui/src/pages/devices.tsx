// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import { Bluetooth, Cable, Copy, Cpu, Loader2, Plus, RefreshCw, Trash2, Usb, Wifi } from "lucide-react";
import { useEffect, useState } from "preact/hooks";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select } from "@/components/ui/select";

interface Device {
  id: string;
  name: string;
  interface_type: string;
  interface_addr: string;
  active: boolean;
  last_seen: string;
  channel_id: string;
}

const IFACE_OPTIONS = [
  { value: "ble",        label: "BLE",        addrPlaceholder: "AA:BB:CC:DD:EE:FF" },
  { value: "serial",     label: "Serial",     addrPlaceholder: "/dev/ttyUSB0" },
  { value: "i2c",        label: "I2C",        addrPlaceholder: "0x68" },
  { value: "usb",        label: "USB",        addrPlaceholder: "/dev/bus/usb/001/002" },
  { value: "zigbee",     label: "Zigbee",     addrPlaceholder: "00:11:22:33:44:55:66:77" },
  { value: "modbus-rtu", label: "Modbus RTU", addrPlaceholder: "/dev/ttyUSB0" },
  { value: "modbus-tcp", label: "Modbus TCP", addrPlaceholder: "192.168.1.10:502" },
];

function ifaceIcon(type: string) {
  switch (type) {
    case "ble": return <Bluetooth className="h-3.5 w-3.5" />;
    case "serial": return <Cable className="h-3.5 w-3.5" />;
    case "usb": return <Usb className="h-3.5 w-3.5" />;
    case "zigbee": return <Wifi className="h-3.5 w-3.5" />;
    default: return <Cpu className="h-3.5 w-3.5" />;
  }
}

function relativeTime(iso: string): string {
  if (!iso || iso.startsWith("0001")) return "never";
  const diff = Date.now() - new Date(iso).getTime();
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

function truncateId(id: string): string {
  if (!id) return "—";
  return id.length > 13 ? `${id.slice(0, 8)}…${id.slice(-4)}` : id;
}

async function extractError(res: Response): Promise<string> {
  try {
    const body = await res.json();
    if (body?.error) return body.error;
    return `HTTP ${res.status}`;
  } catch (parseErr) {
    return `HTTP ${res.status} (${parseErr})`;
  }
}

export function DevicesPage() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [showAdd, setShowAdd] = useState(false);

  const [form, setForm] = useState({
    name: "", ext_id: "", ext_key: "", interface_type: "ble", interface_addr: "",
  });
  const [adding, setAdding] = useState(false);
  const [addError, setAddError] = useState("");

  async function load() {
    setLoading(true);
    setError("");
    try {
      const res = await fetch("/devices");
      if (!res.ok) throw new Error(await extractError(res));
      const data = await res.json();
      setDevices(data.devices ?? []);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  async function handleAdd(e: Event) {
    e.preventDefault();
    setAdding(true);
    setAddError("");
    try {
      const res = await fetch("/devices", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form),
      });
      if (!res.ok) throw new Error(await extractError(res));
      setShowAdd(false);
      setForm({ name: "", ext_id: "", ext_key: "", interface_type: "ble", interface_addr: "" });
      await load();
    } catch (e) {
      setAddError(String(e));
    } finally {
      setAdding(false);
    }
  }

  async function handleRemove(id: string) {
    const name = devices.find((d) => d.id === id)?.name ?? id;
    if (!confirm(`Remove device "${name}"? This will deprovision it from Magistrala.`)) return;
    try {
      const res = await fetch(`/devices/${id}`, { method: "DELETE" });
      if (!res.ok) throw new Error(await extractError(res));
      setDevices((d) => d.filter((x) => x.id !== id));
    } catch (e) {
      setError(String(e));
    }
  }

  async function handleSeen(id: string) {
    try {
      await fetch(`/devices/${id}/seen`, { method: "POST" });
      await load();
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <div className="space-y-[22px]">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-[1.35rem] font-bold leading-tight tracking-tight">Devices</h1>
          <p className="mt-1 text-[0.825rem] text-muted-foreground">
            Downstream devices registered with this gateway.
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="ghost" size="sm" onClick={load} disabled={loading}>
            {loading ? <Loader2 className="h-3 w-3 animate-spin" /> : <RefreshCw className="h-3 w-3" />}
            Refresh
          </Button>
          <Button size="sm" onClick={() => setShowAdd((s) => !s)}>
            <Plus className="h-3 w-3" />
            Add device
          </Button>
        </div>
      </div>

      {showAdd && (
        <Card>
          <CardHeader>
            <CardTitle>
              <Plus className="h-4 w-4" />
              Register new device
            </CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleAdd} className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor="dev-name">Name</Label>
                <Input
                  id="dev-name"
                  placeholder="my-sensor"
                  value={form.name}
                  onInput={(e) => setForm((f) => ({ ...f, name: (e.target as HTMLInputElement).value }))}
                  required
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="dev-iface">Interface type</Label>
                <Select
                  id="dev-iface"
                  value={form.interface_type}
                  onChange={(e) => setForm((f) => ({ ...f, interface_type: (e.target as HTMLSelectElement).value }))}
                >
                  {IFACE_OPTIONS.map((o) => (
                    <option key={o.value} value={o.value}>{o.label}</option>
                  ))}
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="dev-addr">Interface address</Label>
                <Input
                  id="dev-addr"
                  placeholder={IFACE_OPTIONS.find((o) => o.value === form.interface_type)?.addrPlaceholder ?? ""}
                  value={form.interface_addr}
                  onInput={(e) => setForm((f) => ({ ...f, interface_addr: (e.target as HTMLInputElement).value }))}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="dev-extid">External ID <span className="text-muted-foreground font-normal">(unique identifier on your network)</span></Label>
                <Input
                  id="dev-extid"
                  placeholder="e.g. device serial number or MAC"
                  value={form.ext_id}
                  onInput={(e) => setForm((f) => ({ ...f, ext_id: (e.target as HTMLInputElement).value }))}
                  required
                />
              </div>
              <div className="space-y-1.5 sm:col-span-2">
                <Label htmlFor="dev-extkey">External key <span className="text-muted-foreground font-normal">(used to authenticate the provisioning request)</span></Label>
                <Input
                  id="dev-extkey"
                  type="password"
                  placeholder="pre-shared secret or password"
                  value={form.ext_key}
                  onInput={(e) => setForm((f) => ({ ...f, ext_key: (e.target as HTMLInputElement).value }))}
                  required
                />
              </div>
              {addError && (
                <p className="sm:col-span-2 text-sm text-destructive">{addError}</p>
              )}
              <div className="flex gap-2 sm:col-span-2">
                <Button type="submit" size="sm" disabled={adding}>
                  {adding ? <Loader2 className="h-3 w-3 animate-spin" /> : <Plus className="h-3 w-3" />}
                  Register
                </Button>
                <Button type="button" variant="ghost" size="sm" onClick={() => setShowAdd(false)}>
                  Cancel
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      )}

      {error && (
        <div className="rounded-lg border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">
          {error}
        </div>
      )}

      <Card>
        <div>
          {devices.length === 0 ? (
            <div className="px-6 py-11 text-center text-muted-foreground">
              <Cpu className="mx-auto mb-2.5 h-9 w-9 opacity-25" />
              <h3 className="mb-1 text-[0.85rem] font-semibold text-foreground">No devices registered</h3>
              <p className="text-[0.775rem]">Add a downstream device to get started.</p>
            </div>
          ) : (
            devices.map((d) => (
              <div
                key={d.id}
                className="flex items-center gap-[13px] border-b px-[18px] py-[13px] last:border-b-0"
              >
                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-accent text-primary">
                  {ifaceIcon(d.interface_type)}
                </div>
                <div className="min-w-0 flex-1">
                  <div className="text-[0.825rem] font-semibold">{d.name}</div>
                  <div className="truncate font-mono text-[0.7rem] text-muted-foreground">
                    {d.interface_type}
                    {d.interface_addr ? ` · ${d.interface_addr}` : ""}
                    {" · "}last seen {relativeTime(d.last_seen)}
                  </div>
                  {d.channel_id && (
                    <button
                      type="button"
                      title="Copy channel ID"
                      onClick={() => navigator.clipboard.writeText(d.channel_id)}
                      className="mt-0.5 flex items-center gap-1 font-mono text-[0.65rem] text-muted-foreground/60 hover:text-muted-foreground"
                    >
                      <Copy className="h-2.5 w-2.5" />
                      ch: {truncateId(d.channel_id)}
                    </button>
                  )}
                </div>
                <div
                  className={`flex shrink-0 items-center gap-1 rounded-full px-2 py-0.5 text-[0.7rem] font-semibold ${
                    d.active
                      ? "bg-emerald-50 text-emerald-700 dark:bg-emerald-950"
                      : "bg-zinc-100 text-zinc-500 dark:bg-zinc-800"
                  }`}
                >
                  ● {d.active ? "Active" : "Inactive"}
                </div>
                <button
                  type="button"
                  onClick={() => handleSeen(d.id)}
                  className="rounded-lg border px-2.5 py-1 text-[0.75rem] font-medium text-muted-foreground hover:bg-secondary hover:text-foreground"
                  title="Mark as seen"
                >
                  Ping
                </button>
                <button
                  type="button"
                  onClick={() => handleRemove(d.id)}
                  className="rounded-lg border border-destructive/30 px-2 py-1 text-destructive hover:bg-destructive/10"
                  title="Remove device"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </button>
              </div>
            ))
          )}
        </div>
      </Card>
    </div>
  );
}

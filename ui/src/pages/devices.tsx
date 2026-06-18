// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import {
  Bluetooth,
  Cable,
  Copy,
  Cpu,
  Eye,
  EyeOff,
  Loader2,
  LogIn,
  LogOut,
  MessageSquare,
  MoreVertical,
  Plus,
  RefreshCw,
  Trash2,
  Upload,
  Usb,
  Wifi,
} from "lucide-react";
import { useEffect, useState } from "preact/hooks";
import { EmptyState } from "@/components/empty-state";
import { ErrorAlert } from "@/components/error-alert";
import { PageHeader } from "@/components/page-header";
import { StatusBadge } from "@/components/status-badge";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/components/ui/toaster";
import { Tooltip } from "@/components/ui/tooltip";

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
  { value: "ble", label: "BLE", addrPlaceholder: "AA:BB:CC:DD:EE:FF" },
  { value: "serial", label: "Serial", addrPlaceholder: "/dev/ttyUSB0" },
  { value: "i2c", label: "I2C", addrPlaceholder: "0x68" },
  { value: "usb", label: "USB", addrPlaceholder: "/dev/bus/usb/001/002" },
  {
    value: "zigbee",
    label: "Zigbee",
    addrPlaceholder: "00:11:22:33:44:55:66:77",
  },
  { value: "modbus-rtu", label: "Modbus RTU", addrPlaceholder: "/dev/ttyUSB0" },
  {
    value: "modbus-tcp",
    label: "Modbus TCP",
    addrPlaceholder: "192.168.1.10:502",
  },
];

function ifaceIcon(type: string) {
  switch (type) {
    case "ble":
      return <Bluetooth className="size-3.5" />;
    case "serial":
      return <Cable className="size-3.5" />;
    case "usb":
      return <Usb className="size-3.5" />;
    case "zigbee":
      return <Wifi className="size-3.5" />;
    default:
      return <Cpu className="size-3.5" />;
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

function hexDecode(hex: string): string {
  try {
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
      bytes.push(parseInt(hex.slice(i, i + 2), 16));
    }
    return new TextDecoder().decode(new Uint8Array(bytes));
  } catch {
    return hex;
  }
}

function hexEncode(text: string): string {
  const bytes = new TextEncoder().encode(text);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
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
  const { toast } = useToast();
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [showAdd, setShowAdd] = useState(false);

  const [form, setForm] = useState({
    name: "",
    ext_id: "",
    ext_key: "",
    interface_type: "ble",
    interface_addr: "",
  });
  const [adding, setAdding] = useState(false);
  const [addError, setAddError] = useState("");
  const [showExtKey, setShowExtKey] = useState(false);

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

  useEffect(() => {
    load();
  }, []);

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
      setForm({
        name: "",
        ext_id: "",
        ext_key: "",
        interface_type: "ble",
        interface_addr: "",
      });
      toast({ message: "Device registered successfully", variant: "success" });
      await load();
    } catch (e) {
      setAddError(String(e));
    } finally {
      setAdding(false);
    }
  }

  const [removingId, setRemovingId] = useState<string | null>(null);

  async function handleRemove(id: string) {
    setRemovingId(null);
    try {
      const res = await fetch(`/devices/${id}`, { method: "DELETE" });
      if (!res.ok) throw new Error(await extractError(res));
      setDevices((d) => d.filter((x) => x.id !== id));
      toast({ message: "Device removed", variant: "success" });
    } catch (e) {
      setError(String(e));
      toast({ message: String(e), variant: "error" });
    }
  }

  async function handleSeen(id: string) {
    try {
      await fetch(`/devices/${id}/seen`, { method: "POST" });
      toast({ message: "Device marked as seen", variant: "success" });
      await load();
    } catch (e) {
      setError(String(e));
    }
  }

  async function handleOpen(id: string) {
    try {
      const res = await fetch(`/devices/${id}/open`, { method: "POST" });
      if (!res.ok) throw new Error(await extractError(res));
      toast({ message: "Interface opened", variant: "success" });
      setError("");
    } catch (e) {
      setError(`Open failed: ${e}`);
    }
  }

  async function handleClose(id: string) {
    try {
      const res = await fetch(`/devices/${id}/close`, { method: "POST" });
      if (!res.ok) throw new Error(await extractError(res));
      toast({ message: "Interface closed", variant: "success" });
      setError("");
    } catch (e) {
      setError(`Close failed: ${e}`);
    }
  }

  async function handleRead(id: string) {
    try {
      const res = await fetch(`/devices/${id}/read`, {
        method: "POST",
        body: "{}",
      });
      if (!res.ok) throw new Error(await extractError(res));
      const data = await res.json();
      const dataStr =
        typeof data.data === "string" ? data.data : JSON.stringify(data.data);
      setError("");
      setReadResult({ id, data: dataStr });
    } catch (e) {
      setError(`Read failed: ${e}`);
    }
  }

  const [readResult, setReadResult] = useState<{
    id: string;
    data: string;
  } | null>(null);
  const [writeDialog, setWriteDialog] = useState<string | null>(null);
  const [writeText, setWriteText] = useState("");

  async function handleWrite(id: string) {
    if (writeDialog !== id) {
      setWriteDialog(id);
      setWriteText("");
      return;
    }
    if (!writeText.trim()) return;
    try {
      const res = await fetch(`/devices/${id}/write`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ data: hexEncode(writeText) }),
      });
      if (!res.ok) throw new Error(await extractError(res));
      setWriteDialog(null);
      setWriteText("");
      toast({ message: "Data written to device", variant: "success" });
      setError("");
    } catch (e) {
      setError(`Write failed: ${e}`);
    }
  }

  function copyChannelId(channelId: string) {
    navigator.clipboard.writeText(channelId);
    toast({ message: "Channel ID copied", variant: "success" });
  }

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Devices"
        subtitle="Downstream devices registered with this gateway."
        actions={
          <div className="flex gap-2">
            <Button variant="ghost" size="sm" onClick={load} disabled={loading}>
              {loading ? (
                <Loader2 className="size-3 animate-spin" />
              ) : (
                <RefreshCw className="size-3" />
              )}
              Refresh
            </Button>
            <Button size="sm" onClick={() => setShowAdd((s) => !s)}>
              <Plus className="size-3" />
              Add device
            </Button>
          </div>
        }
      />

      {showAdd && (
        <Card>
          <CardHeader>
            <CardTitle>
              <Plus className="size-4" />
              Register new device
            </CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleAdd} className="grid gap-4 sm:grid-cols-2">
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="dev-name">Name</Label>
                <Input
                  id="dev-name"
                  placeholder="my-sensor"
                  value={form.name}
                  onInput={(e) =>
                    setForm((f) => ({
                      ...f,
                      name: (e.target as HTMLInputElement).value,
                    }))
                  }
                  required
                />
              </div>
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="dev-iface">Interface type</Label>
                <Select
                  id="dev-iface"
                  value={form.interface_type}
                  onChange={(e) =>
                    setForm((f) => ({
                      ...f,
                      interface_type: (e.target as HTMLSelectElement).value,
                    }))
                  }
                >
                  {IFACE_OPTIONS.map((o) => (
                    <option key={o.value} value={o.value}>
                      {o.label}
                    </option>
                  ))}
                </Select>
              </div>
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="dev-addr">Interface address</Label>
                <Input
                  id="dev-addr"
                  placeholder={
                    IFACE_OPTIONS.find((o) => o.value === form.interface_type)
                      ?.addrPlaceholder ?? ""
                  }
                  value={form.interface_addr}
                  onInput={(e) =>
                    setForm((f) => ({
                      ...f,
                      interface_addr: (e.target as HTMLInputElement).value,
                    }))
                  }
                />
              </div>
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="dev-extid">External ID</Label>
                <Input
                  id="dev-extid"
                  placeholder="e.g. device serial number or MAC"
                  value={form.ext_id}
                  onInput={(e) =>
                    setForm((f) => ({
                      ...f,
                      ext_id: (e.target as HTMLInputElement).value,
                    }))
                  }
                  required
                />
              </div>
              <div className="flex flex-col gap-1.5 sm:col-span-2">
                <Label htmlFor="dev-extkey">External key</Label>
                <div className="relative">
                  <Input
                    id="dev-extkey"
                    type={showExtKey ? "text" : "password"}
                    placeholder="pre-shared secret or password"
                    value={form.ext_key}
                    onInput={(e) =>
                      setForm((f) => ({
                        ...f,
                        ext_key: (e.target as HTMLInputElement).value,
                      }))
                    }
                    required
                    className="pr-10"
                  />
                  <button
                    type="button"
                    onClick={() => setShowExtKey((v) => !v)}
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                    tabIndex={-1}
                    aria-label={showExtKey ? "Hide password" : "Show password"}
                  >
                    {showExtKey ? (
                      <EyeOff className="size-4" />
                    ) : (
                      <Eye className="size-4" />
                    )}
                  </button>
                </div>
              </div>
              <ErrorAlert error={addError} className="sm:col-span-2" />
              <div className="flex gap-2 sm:col-span-2">
                <Button type="submit" size="sm" disabled={adding}>
                  {adding ? (
                    <Loader2 className="size-3 animate-spin" />
                  ) : (
                    <Plus className="size-3" />
                  )}
                  Register
                </Button>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  onClick={() => setShowAdd(false)}
                >
                  Cancel
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      )}

      <ErrorAlert error={error} />

      <Card>
        <div>
          {devices.length === 0 ? (
            <EmptyState
              icon={<Cpu className="size-9" />}
              title="No devices registered"
              description="Add a downstream device to get started."
            />
          ) : (
            devices.map((d) => (
              <div
                key={d.id}
                className="flex items-center gap-3 border-b px-4 py-3 last:border-b-0"
              >
                <div className="flex size-8 shrink-0 items-center justify-center rounded-md bg-accent text-primary">
                  {ifaceIcon(d.interface_type)}
                </div>
                <div className="min-w-0 flex-1">
                  <div className="text-sm font-semibold">{d.name}</div>
                  <div className="truncate font-mono text-xs text-muted-foreground">
                    {d.interface_type}
                    {d.interface_addr ? ` · ${d.interface_addr}` : ""}
                    {" · "}last seen {relativeTime(d.last_seen)}
                  </div>
                  {d.channel_id && (
                    <button
                      type="button"
                      onClick={() => copyChannelId(d.channel_id)}
                      className="mt-0.5 flex items-center gap-1 font-mono text-xs text-muted-foreground/60 transition-colors hover:text-muted-foreground"
                    >
                      <Copy className="size-2.5" />
                      ch: {truncateId(d.channel_id)}
                    </button>
                  )}
                </div>
                <StatusBadge
                  status={d.active ? "active" : "inactive"}
                  label={d.active ? "Active" : "Inactive"}
                />
                <div className="flex items-center gap-1">
                  <Tooltip content="Open interface" side="bottom">
                    <Button
                      variant="ghost"
                      size="icon"
                      className="size-7"
                      onClick={() => handleOpen(d.id)}
                    >
                      <LogIn className="size-3" />
                    </Button>
                  </Tooltip>
                  <Tooltip content="Close interface" side="bottom">
                    <Button
                      variant="ghost"
                      size="icon"
                      className="size-7"
                      onClick={() => handleClose(d.id)}
                    >
                      <LogOut className="size-3" />
                    </Button>
                  </Tooltip>
                  <Tooltip content="Read from interface" side="bottom">
                    <Button
                      variant="ghost"
                      size="icon"
                      className="size-7"
                      onClick={() => handleRead(d.id)}
                    >
                      <MessageSquare className="size-3" />
                    </Button>
                  </Tooltip>
                  <Tooltip content="Write to interface" side="bottom">
                    <Button
                      variant="ghost"
                      size="icon"
                      className="size-7"
                      onClick={() => handleWrite(d.id)}
                    >
                      <Upload className="size-3" />
                    </Button>
                  </Tooltip>
                  <DropdownMenu>
                    <DropdownMenuTrigger
                      className="flex size-7 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
                      title="More actions"
                    >
                      <MoreVertical className="size-3.5" />
                    </DropdownMenuTrigger>
                    <DropdownMenuContent>
                      <DropdownMenuItem onClick={() => handleSeen(d.id)}>
                        Ping
                      </DropdownMenuItem>
                      <DropdownMenuItem
                        variant="destructive"
                        onClick={() => setRemovingId(d.id)}
                      >
                        <Trash2 className="size-3.5" />
                        Remove
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </div>
              </div>
            ))
          )}
        </div>
      </Card>

      <Dialog
        open={!!readResult}
        onOpenChange={(v) => {
          if (!v) setReadResult(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              Read from{" "}
              {devices.find((d) => d.id === readResult?.id)?.name ??
                readResult?.id?.slice(0, 8)}
            </DialogTitle>
            <DialogDescription>
              Data read from the device interface.
            </DialogDescription>
          </DialogHeader>
          <Textarea
            value={readResult?.data ? hexDecode(readResult.data) : ""}
            readOnly
            rows={6}
            className="font-mono text-xs"
          />
          <div className="mt-4 flex justify-end">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setReadResult(null)}
            >
              Close
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      <Dialog
        open={!!writeDialog}
        onOpenChange={(v) => {
          if (!v) setWriteDialog(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              Write to{" "}
              {devices.find((d) => d.id === writeDialog)?.name ??
                writeDialog?.slice(0, 8)}
            </DialogTitle>
            <DialogDescription>
              Enter text to send to the device.
            </DialogDescription>
          </DialogHeader>
          <Textarea
            value={writeText}
            onInput={(e) =>
              setWriteText((e.target as HTMLTextAreaElement).value)
            }
            placeholder="type your message here…"
            rows={4}
            className="font-mono text-xs"
          />
          <div className="mt-4 flex justify-end gap-2">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                setWriteDialog(null);
                setWriteText("");
              }}
            >
              Cancel
            </Button>
            <Button
              size="sm"
              disabled={!writeText.trim()}
              onClick={() => writeDialog && handleWrite(writeDialog)}
            >
              <Upload className="size-3" />
              Send
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      <AlertDialog
        open={!!removingId}
        onOpenChange={(v) => {
          if (!v) setRemovingId(null);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Remove device</AlertDialogTitle>
            <AlertDialogDescription>
              Remove device "
              {devices.find((d) => d.id === removingId)?.name ?? removingId}"?
              This will deprovision it from Magistrala.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={() => removingId && handleRemove(removingId)}
            >
              Remove
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

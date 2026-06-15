// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import {
  Cpu,
  Download,
  Gauge,
  HardDriveDownload,
  HeartPulse,
  type LucideIcon,
  Radio,
  RadioTower,
  ScrollText,
  Settings,
  SquareTerminal,
  Terminal,
  Workflow,
} from "lucide-react";
import { UI_BASE } from "@/routes";

export interface NavItem {
  href: string;
  label: string;
  icon: LucideIcon;
}

export interface NavGroup {
  label: string;
  items: NavItem[];
}

export const navGroups: NavGroup[] = [
  {
    label: "Monitor",
    items: [
      { href: `${UI_BASE}/`, label: "Overview", icon: Gauge },
      { href: `${UI_BASE}/telemetry`, label: "Telemetry", icon: Radio },
      { href: `${UI_BASE}/health`, label: "Health", icon: HeartPulse },
      {
        href: `${UI_BASE}/services`,
        label: "Services",
        icon: HardDriveDownload,
      },
      { href: `${UI_BASE}/logs`, label: "Logs", icon: ScrollText },
    ],
  },
  {
    label: "Control",
    items: [
      { href: `${UI_BASE}/devices`, label: "Devices", icon: Cpu },
      { href: `${UI_BASE}/exec`, label: "Execute", icon: Terminal },
      { href: `${UI_BASE}/terminal`, label: "Terminal", icon: SquareTerminal },
      { href: `${UI_BASE}/nodered`, label: "Node-RED", icon: Workflow },
    ],
  },
  {
    label: "System",
    items: [
      { href: `${UI_BASE}/config`, label: "Configuration", icon: Settings },
      { href: `${UI_BASE}/ota`, label: "OTA Update", icon: Download },
      { href: `${UI_BASE}/bootstrap`, label: "Bootstrap", icon: RadioTower },
    ],
  },
];

export function isActivePath(path: string, href: string): boolean {
  if (href === `${UI_BASE}/`) {
    return path === UI_BASE || path === `${UI_BASE}/`;
  }
  return path === href || path.startsWith(`${href}/`);
}

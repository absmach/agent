// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDuration(
  value: string | number | null | undefined,
): string {
  if (value == null) return "—";

  let ns: number;
  if (typeof value === "number") {
    ns = value;
  } else {
    const s = value.trim();
    if (s === "" || s === "0s") return "—";
    if (/^\d+(?:\.\d+)?$/.test(s)) {
      ns = Number(s);
    } else {
      return s;
    }
  }

  if (ns <= 0) return "—";

  const totalSeconds = Math.round(ns / 1e9);
  const h = Math.floor(totalSeconds / 3600);
  const m = Math.floor((totalSeconds % 3600) / 60);
  const sec = totalSeconds % 60;

  const parts: string[] = [];
  if (h > 0) parts.push(`${h}h`);
  if (m > 0) parts.push(`${m}m`);
  if (sec > 0 || parts.length === 0) parts.push(`${sec}s`);

  return parts.join("");
}

export function formatBytes(bytes: number | null | undefined): string {
  if (bytes == null || bytes <= 0) return "—";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let val = bytes;
  let i = 0;
  while (val >= 1024 && i < units.length - 1) {
    val /= 1024;
    i++;
  }
  return `${val.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

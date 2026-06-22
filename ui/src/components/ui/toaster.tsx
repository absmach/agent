// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import { AlertCircle, CheckCircle2, Info, X, XCircle } from "lucide-react";
import { type ComponentChildren, createContext } from "preact";
import { useCallback, useContext, useEffect, useState } from "preact/hooks";
import { cn } from "@/lib/utils";

export interface ToastOptions {
  message: ComponentChildren;
  variant?: "default" | "success" | "error" | "warning";
  duration?: number;
}

interface ToastItem extends ToastOptions {
  id: number;
}

interface ToastContextValue {
  toast: (opts: ToastOptions) => void;
}

const ToastContext = createContext<ToastContextValue>({
  toast: () => {},
});

let toastId = 0;

export function ToastProvider({ children }: { children: ComponentChildren }) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  const remove = useCallback((id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const toast = useCallback(
    (opts: ToastOptions) => {
      const id = ++toastId;
      const duration = opts.duration ?? 4000;
      setToasts((prev) => [...prev, { ...opts, id }]);
      if (duration > 0) {
        setTimeout(() => remove(id), duration);
      }
    },
    [remove],
  );

  return (
    <ToastContext.Provider value={{ toast }}>
      {children}
      <div className="pointer-events-none fixed bottom-4 right-4 z-[100] flex flex-col gap-2">
        {toasts.map((t) => (
          <ToastItemView key={t.id} toast={t} onClose={() => remove(t.id)} />
        ))}
      </div>
    </ToastContext.Provider>
  );
}

const variantConfig = {
  default: {
    icon: Info,
    className: "bg-card text-card-foreground border-border",
  },
  success: {
    icon: CheckCircle2,
    className: "bg-card text-card-foreground border-success/40",
  },
  error: {
    icon: XCircle,
    className: "bg-card text-card-foreground border-destructive/40",
  },
  warning: {
    icon: AlertCircle,
    className: "bg-card text-card-foreground border-amber-500/40",
  },
};

function ToastItemView({
  toast,
  onClose,
}: {
  toast: ToastItem;
  onClose: () => void;
}) {
  const config = variantConfig[toast.variant ?? "default"];
  const Icon = config.icon;

  useEffect(() => {
    const el = document.createElement("div");
    return () => el.remove();
  }, []);

  return (
    <div
      role="status"
      className={cn(
        "pointer-events-auto flex w-80 items-start gap-3 rounded-lg border p-4 shadow-lg",
        "animate-in slide-in-from-bottom-2 fade-in duration-200",
        config.className,
      )}
    >
      <Icon
        className={cn(
          "mt-0.5 size-4 shrink-0",
          toast.variant === "success" && "text-success",
          toast.variant === "error" && "text-destructive",
          toast.variant === "warning" && "text-amber-500",
        )}
      />
      <div className="flex-1 text-sm">{toast.message}</div>
      <button
        type="button"
        onClick={onClose}
        className="rounded-sm opacity-70 transition-opacity hover:opacity-100"
      >
        <X className="size-3.5" />
        <span className="sr-only">Close</span>
      </button>
    </div>
  );
}

export function useToast() {
  return useContext(ToastContext);
}

// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import { ConfigCard } from "@/components/config-card";

export function ConfigPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Configuration</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          View and update the agent runtime settings
        </p>
      </div>
      <div className="max-w-xl">
        <ConfigCard />
      </div>
    </div>
  );
}

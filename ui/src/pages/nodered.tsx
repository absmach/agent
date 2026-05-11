// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import { NodeRedCard } from "@/components/nodered-card";

export function NodeRedPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Node-RED</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Manage Node-RED flows and deployment
        </p>
      </div>
      <div className="max-w-xl">
        <NodeRedCard />
      </div>
    </div>
  );
}

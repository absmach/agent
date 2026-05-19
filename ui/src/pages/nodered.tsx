// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import { NodeRedCard } from "@/components/nodered-card";

export function NodeRedPage() {
  return (
    <div className="space-y-[22px]">
      <div>
        <h1 className="text-[1.35rem] font-bold leading-tight tracking-tight">
          Node-RED
        </h1>
        <p className="mt-1 text-[0.825rem] text-muted-foreground">
          Manage Node-RED flows and deployment
        </p>
      </div>
      <NodeRedCard />
    </div>
  );
}

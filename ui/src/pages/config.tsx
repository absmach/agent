// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import { ConfigCard } from "@/components/config-card";

export function ConfigPage() {
  return (
    <div className="space-y-[22px]">
      <div>
        <h1 className="text-[1.35rem] font-bold leading-tight tracking-tight">
          Configuration
        </h1>
        <p className="mt-1 text-[0.825rem] text-muted-foreground">
          View and update the agent runtime settings
        </p>
      </div>
      <div className="max-w-2xl">
        <ConfigCard />
      </div>
    </div>
  );
}

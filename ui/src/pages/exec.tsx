// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import { ExecCard } from "@/components/exec-card";

export function ExecPage() {
  return (
    <div className="space-y-[22px]">
      <div>
        <h1 className="text-[1.35rem] font-bold leading-tight tracking-tight">
          Execute Command
        </h1>
        <p className="mt-1 text-[0.825rem] text-muted-foreground">
          Run shell commands on the device through the agent
        </p>
      </div>
      <div className="max-w-3xl">
        <ExecCard />
      </div>
    </div>
  );
}

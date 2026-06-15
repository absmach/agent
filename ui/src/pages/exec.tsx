// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import { ExecCard } from "@/components/exec-card";
import { PageHeader } from "@/components/page-header";

export function ExecPage() {
  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Execute Command"
        subtitle="Run shell commands on the device through the agent"
      />
      <ExecCard />
    </div>
  );
}

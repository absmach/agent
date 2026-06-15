// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import { NodeRedCard } from "@/components/nodered-card";
import { PageHeader } from "@/components/page-header";

export function NodeRedPage() {
  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Node-RED"
        subtitle="Manage Node-RED flows and deployment"
      />
      <NodeRedCard />
    </div>
  );
}

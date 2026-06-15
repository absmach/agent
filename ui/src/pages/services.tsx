// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import { PageHeader } from "@/components/page-header";
import { ServicesCard } from "@/components/services-card";

export function ServicesPage() {
  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Services"
        subtitle="Registered services and their current status"
      />
      <ServicesCard />
    </div>
  );
}

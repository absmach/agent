// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import { ServicesCard } from "@/components/services-card";

export function ServicesPage() {
  return (
    <div className="space-y-[22px]">
      <div>
        <h1 className="text-[1.35rem] font-bold leading-tight tracking-tight">
          Services
        </h1>
        <p className="mt-1 text-[0.825rem] text-muted-foreground">
          Registered services and their current status
        </p>
      </div>
      <ServicesCard />
    </div>
  );
}

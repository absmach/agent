// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import { LocationProvider, Route, Router } from "preact-iso";
import { Shell } from "@/components/layout/shell";
import { BootstrapPage } from "@/pages/bootstrap";
import { ConfigPage } from "@/pages/config";
import { DevicesPage } from "@/pages/devices";
import { HealthPage } from "@/pages/health";
import { HomePage } from "@/pages/home";
import { LogsPage } from "@/pages/logs";
import { NodeRedPage } from "@/pages/nodered";
import { OTAPage } from "@/pages/ota";
import { ServicesPage } from "@/pages/services";
import { TelemetryPage } from "@/pages/telemetry";
import { TerminalPage } from "@/pages/terminal";
import { UI_BASE } from "@/routes";

export function App() {
  return (
    <LocationProvider>
      <Shell>
        <Router>
          <Route path={`${UI_BASE}/`} component={HomePage} />
          <Route path={UI_BASE} component={HomePage} />
          <Route path={`${UI_BASE}/config`} component={ConfigPage} />
          <Route path={`${UI_BASE}/services`} component={ServicesPage} />
          <Route path={`${UI_BASE}/nodered`} component={NodeRedPage} />
          <Route path={`${UI_BASE}/devices`} component={DevicesPage} />
          <Route path={`${UI_BASE}/ota`} component={OTAPage} />
          <Route path={`${UI_BASE}/logs`} component={LogsPage} />
          <Route path={`${UI_BASE}/health`} component={HealthPage} />
          <Route path={`${UI_BASE}/telemetry`} component={TelemetryPage} />
          <Route path={`${UI_BASE}/bootstrap`} component={BootstrapPage} />
          <Route path={`${UI_BASE}/terminal`} component={TerminalPage} />
        </Router>
      </Shell>
    </LocationProvider>
  );
}

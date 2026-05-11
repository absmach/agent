// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import { LocationProvider, Route, Router } from "preact-iso";
import { Shell } from "@/components/layout/shell";
import { ConfigPage } from "@/pages/config";
import { ExecPage } from "@/pages/exec";
import { HomePage } from "@/pages/home";
import { NodeRedPage } from "@/pages/nodered";
import { ServicesPage } from "@/pages/services";

export function App() {
  return (
    <LocationProvider>
      <Shell>
        <Router>
          <Route path="/" component={HomePage} />
          <Route path="/config" component={ConfigPage} />
          <Route path="/services" component={ServicesPage} />
          <Route path="/exec" component={ExecPage} />
          <Route path="/nodered" component={NodeRedPage} />
        </Router>
      </Shell>
    </LocationProvider>
  );
}

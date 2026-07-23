// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import { render } from "preact";
import { App } from "./app";
import "./app.css";
import { agentFetch } from "./lib/transport";

globalThis.fetch = agentFetch;

const root = document.getElementById("app");
if (root) {
  render(<App />, root);
}

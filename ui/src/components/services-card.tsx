// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Activity, Info, Loader2 } from "lucide-react";
import { useState } from "preact/hooks";

export function ServicesCard() {
  const [services, setServices] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function refresh() {
    setLoading(true);
    setError("");
    try {
      const res = await fetch("/services");
      const text = await res.text();
      try {
        setServices(JSON.stringify(JSON.parse(text), null, 2));
      } catch {
        setServices(text);
      }
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <Activity className="h-4 w-4" />
          Services
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <Button variant="outline" size="sm" onClick={refresh} disabled={loading}>
          {loading ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" />
              Refreshing…
            </>
          ) : (
            "Refresh"
          )}
        </Button>

        {error && <p className="text-sm text-destructive">{error}</p>}

        {!loading && !error && services ? (
          <pre className="max-h-56 overflow-y-auto rounded-md border bg-muted/50 p-3 text-xs">
            {services}
          </pre>
        ) : (
          !loading &&
          !error && (
            <p className="flex items-center gap-2 text-sm text-muted-foreground">
              <Info className="h-4 w-4" />
              No services registered yet.
            </p>
          )
        )}
      </CardContent>
    </Card>
  );
}

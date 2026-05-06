import { NextResponse } from "next/server";

const AGENT = process.env.AGENT_BASE_URL ?? "http://localhost:9999";

export async function GET() {
  try {
    const res = await fetch(`${AGENT}/config`, {
      cache: "no-store",
      signal: AbortSignal.timeout(3000),
    });

    return NextResponse.json({ reachable: true, status: res.status, agentUrl: AGENT });
  } catch {
    return NextResponse.json({ reachable: false, agentUrl: AGENT });
  }
}

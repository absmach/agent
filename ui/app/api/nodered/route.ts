import { type NextRequest, NextResponse } from "next/server";

const AGENT = process.env.AGENT_BASE_URL ?? "http://localhost:9999";

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const res = await fetch(`${AGENT}/nodered`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    return NextResponse.json(data, { status: res.status });
  } catch {
    return NextResponse.json(
      { error: "Failed to reach agent" },
      { status: 502 },
    );
  }
}

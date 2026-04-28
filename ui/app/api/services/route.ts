import { NextResponse } from "next/server";

const AGENT = process.env.AGENT_BASE_URL ?? "http://localhost:9999";

export async function GET() {
  try {
    const res = await fetch(`${AGENT}/services`, { cache: "no-store" });
    const text = await res.text();
    return new NextResponse(text, {
      status: res.status,
      headers: { "Content-Type": "application/json" },
    });
  } catch {
    return NextResponse.json(
      { error: "Failed to reach agent" },
      { status: 502 },
    );
  }
}

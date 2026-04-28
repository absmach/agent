import { ExecCard } from "@/components/exec-card";

export default function ExecPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">
          Execute Command
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Run shell commands on the device through the agent
        </p>
      </div>
      <div className="max-w-3xl">
        <ExecCard />
      </div>
    </div>
  );
}

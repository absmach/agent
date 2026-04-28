import { ConfigCard } from "@/components/config-card";
import { ExecCard } from "@/components/exec-card";
import { NodeRedCard } from "@/components/nodered-card";
import { ServicesCard } from "@/components/services-card";

export default function Home() {
  return (
    <main className="min-h-screen bg-background">
      <div className="container mx-auto px-4 py-8 max-w-6xl">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-foreground tracking-tight">
            Magistrala Agent
          </h1>
          <p className="text-muted-foreground mt-1 text-sm">
            Manage configuration, Node-RED flows, services and commands
          </p>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <ConfigCard />
          <NodeRedCard />
          <ServicesCard />
          <ExecCard />
        </div>
      </div>
    </main>
  );
}

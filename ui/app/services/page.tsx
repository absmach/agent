import { ServicesCard } from "@/components/services-card";

export default function ServicesPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Services</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Registered services and their current status
        </p>
      </div>
      <div className="max-w-xl">
        <ServicesCard />
      </div>
    </div>
  );
}

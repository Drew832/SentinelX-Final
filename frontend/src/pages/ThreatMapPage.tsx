import ThreatMap from "@/components/map/ThreatMap";

export default function ThreatMapPage() {
  return (
    <div className="space-y-5">
      <div>
        <h1 className="page-heading">Threat Map</h1>
        <div className="page-underline" />
        <p className="page-subtitle">
          A geographic view of where today's top KEV-listed CVEs are showing up online.
          Bigger pulses mean active CISA-confirmed exploitation; colour follows CVSS severity.
        </p>
      </div>
      <ThreatMap />
    </div>
  );
}

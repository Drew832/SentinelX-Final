import { useEffect, useMemo, useState } from "react";
import { MapContainer, Marker, Popup, TileLayer } from "react-leaflet";
import L, { divIcon } from "leaflet";
import { telemetryApi } from "@/api/endpoints";
import type { TelemetryPoint, TelemetryResponse } from "@/types";
import { severityColor, formatDate } from "@/utils/format";

// Leaflet's default icon assets break under bundlers; we use a custom div icon so this is fine.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
delete (L.Icon.Default.prototype as any)._getIconUrl;

function buildPulseIcon(point: TelemetryPoint) {
  const color = severityColor(point.cvss_v3_severity, point.cvss_v3_score);
  const isKev = point.is_kev;
  const size = isKev ? 22 : 14;
  return divIcon({
    className: "",
    iconSize: [size, size],
    html: `
      <div class="threat-marker ${isKev ? "threat-marker--kev" : ""}"
           style="color:${color}; width:${size}px; height:${size}px;">
        <span class="threat-marker__pulse"></span>
        <span class="threat-marker__core"
              style="background:${color};
                     border:2px solid ${isKev ? "#fff" : "rgba(255,255,255,0.6)"};
                     box-shadow:0 0 ${isKev ? 24 : 12}px ${color};"></span>
      </div>
    `,
  });
}

export default function ThreatMap() {
  const [data, setData] = useState<TelemetryResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    telemetryApi
      .fetch()
      .then((d) => {
        if (!cancelled) setData(d);
      })
      .catch((e) => {
        if (!cancelled) setError(e?.message || "Failed to load telemetry");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const stats = useMemo(() => {
    if (!data) return { kev: 0, total: 0 };
    return {
      total: data.points.length,
      kev: data.points.filter((p) => p.is_kev).length,
    };
  }, [data]);

  return (
    <div className="panel-dark overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/10 px-5 py-3">
        <div>
          <div className="text-sm font-semibold uppercase tracking-wider text-sentinel-gold">
            Active Threat Telemetry
          </div>
          <div className="text-xs text-slate-500">
            {data?.source === "shodan" ? "Shodan live correlation" : "Representative geo distribution"}
            {" · "}
            {stats.total} points · {stats.kev} weaponized
            {data?.cached && " · cached"}
          </div>
          {data?.note && (
            <div className="mt-1 max-w-xl text-[11px] text-amber-300/80">{data.note}</div>
          )}
        </div>
        <div className="flex items-center gap-3 text-xs">
          {[
            { label: "Critical 9.0+", color: "#ef4444" },
            { label: "High 7.0–8.9", color: "#f97316" },
            { label: "Medium", color: "#facc15" },
            { label: "Low", color: "#10b981" },
          ].map((l) => (
            <div key={l.label} className="flex items-center gap-1 text-slate-400">
              <span
                className="inline-block h-2.5 w-2.5 rounded-full"
                style={{ background: l.color, boxShadow: `0 0 8px ${l.color}` }}
              />
              {l.label}
            </div>
          ))}
        </div>
      </div>

      <div className="h-[560px] w-full">
        {loading && (
          <div className="flex h-full items-center justify-center text-slate-400">
            Initializing satellite feed…
          </div>
        )}
        {error && (
          <div className="flex h-full items-center justify-center text-red-300">{error}</div>
        )}
        {!loading && !error && data && (
          <MapContainer
            center={[20, 0]}
            zoom={2}
            scrollWheelZoom
            worldCopyJump
            className="h-full w-full"
          >
            <TileLayer
              attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
              url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
            />
            {data.points.map((p, idx) => (
              <Marker
                key={`${p.cve_id}-${idx}`}
                position={[p.latitude, p.longitude]}
                icon={buildPulseIcon(p)}
              >
                <Popup>
                  <div className="font-mono text-xs">
                    <div className="font-semibold text-base text-red-600">
                      {p.cve_id}
                      {p.is_kev && " ⚡ KEV"}
                    </div>
                    {p.kev_vulnerability_name && (
                      <div className="mt-1 text-slate-700">{p.kev_vulnerability_name}</div>
                    )}
                    <div className="mt-1 text-slate-600">
                      CVSS {p.cvss_v3_score ?? "—"} · {p.cvss_v3_severity || "N/A"}
                    </div>
                    <div className="mt-1 text-slate-600">IP: {p.ip_obfuscated}</div>
                    <div className="text-slate-600">
                      {p.city ? `${p.city}, ` : ""}
                      {p.country || "Unknown"}
                    </div>
                    {p.org && <div className="text-slate-500">Org: {p.org}</div>}
                  </div>
                </Popup>
              </Marker>
            ))}
          </MapContainer>
        )}
      </div>
      {data && (
        <div className="border-t border-white/10 px-5 py-2 text-right text-[11px] text-slate-400">
          Generated {formatDate(data.generated_at)}
        </div>
      )}
    </div>
  );
}

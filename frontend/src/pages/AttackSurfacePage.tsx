import { useEffect, useMemo, useState } from "react";
import { MapContainer, Marker, Popup, TileLayer } from "react-leaflet";
import L, { divIcon } from "leaflet";
import { cveApi, geoApi } from "@/api/endpoints";
import type { CVE } from "@/types";
import { severityColor } from "@/utils/format";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
delete (L.Icon.Default.prototype as any)._getIconUrl;

function buildIcon(severity: string, score: number | null, kev: boolean) {
  const color = severityColor(severity, score);
  const size = kev ? 22 : 14;
  return divIcon({
    className: "",
    iconSize: [size, size],
    html: `
      <div class="threat-marker ${kev ? "threat-marker--kev" : ""}" style="color:${color}; width:${size}px; height:${size}px;">
        <span class="threat-marker__pulse"></span>
        <span class="threat-marker__core"
              style="background:${color};
                     border:2px solid ${kev ? "#fff" : "rgba(255,255,255,0.6)"};
                     box-shadow:0 0 ${kev ? 24 : 12}px ${color};"></span>
      </div>
    `,
  });
}

export default function AttackSurfacePage() {
  const [cves, setCves] = useState<CVE[]>([]);
  const [selected, setSelected] = useState<string>("");
  const [data, setData] = useState<Awaited<ReturnType<typeof geoApi.fetchForCve>> | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    cveApi
      .list({ only_kev: true, sort: "score_desc", page_size: 30 })
      .then((res) => {
        setCves(res.items);
        if (res.items.length) setSelected(res.items[0].cve_id);
      });
  }, []);

  useEffect(() => {
    if (!selected) return;
    setLoading(true);
    setError(null);
    geoApi
      .fetchForCve(selected)
      .then(setData)
      .catch((e) => setError(e?.message || "Failed to fetch geo data"))
      .finally(() => setLoading(false));
  }, [selected]);

  const counts = useMemo(() => {
    if (!data) return { total: 0, countries: 0 };
    return {
      total: data.points.length,
      countries: new Set(data.points.map((p) => p.country || "—")).size,
    };
  }, [data]);

  return (
    <div className="space-y-5">
      <div>
        <h1 className="page-heading">Attack Surface Map</h1>
        <div className="page-underline" />
        <p className="page-subtitle">
          Pick a CVE — we'll ask Shodan where vulnerable hosts are sitting on the public
          internet right now and pin them on the map.
        </p>
      </div>

      <div className="panel-pad flex flex-wrap items-end gap-3">
        <div className="flex-1 min-w-[260px]">
          <label className="label">Select CVE (top KEV entries)</label>
          <select
            className="input"
            value={selected}
            onChange={(e) => setSelected(e.target.value)}
          >
            {cves.map((c) => (
              <option key={c.cve_id} value={c.cve_id}>
                {c.cve_id} · {c.cvss_v3_severity || "—"} · {(c.vendors || [])[0] || "—"}
              </option>
            ))}
          </select>
        </div>
        <div className="text-sm text-slate-500">
          {counts.total} points · {counts.countries} countries
        </div>
      </div>

      {error && <div className="panel-pad text-red-500">{error}</div>}

      <div className="panel-dark overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/10 px-5 py-3 text-white">
          <div>
            <div className="text-sm font-semibold uppercase tracking-wider text-sentinel-gold">
              Geo-located Exposure
            </div>
            <div className="text-xs text-slate-400">
              Source: <span className="uppercase">{data?.source || "—"}</span>
            </div>
          </div>
          <div className="flex items-center gap-3 text-xs">
            {[
              { label: "Critical 9.0+", color: "#ef4444" },
              { label: "High 7.0–8.9", color: "#f97316" },
              { label: "Medium", color: "#facc15" },
              { label: "Low", color: "#10b981" },
            ].map((l) => (
              <div key={l.label} className="flex items-center gap-1 text-slate-300">
                <span
                  className="inline-block h-2.5 w-2.5 rounded-full"
                  style={{ background: l.color, boxShadow: `0 0 8px ${l.color}` }}
                />
                {l.label}
              </div>
            ))}
          </div>
        </div>

        {data?.note && (
          <div className="border-b border-white/10 px-5 py-2 text-xs text-amber-300/90">
            {data.note}
          </div>
        )}

        <div className="h-[560px] w-full">
          {loading && (
            <div className="flex h-full items-center justify-center text-slate-300">
              Querying telemetry…
            </div>
          )}
          {!loading && data && (
            <MapContainer
              key={data.cve_id}
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
              {data.points.map((p, i) => (
                <Marker
                  key={`${p.cve_id}-${i}`}
                  position={[p.latitude, p.longitude]}
                  icon={buildIcon(p.severity, p.cvss_v3_score, p.is_kev)}
                >
                  <Popup>
                    <div className="font-mono text-xs">
                      <div className="text-sm font-bold text-red-600">{p.cve_id}</div>
                      <div className="mt-1 text-slate-700">
                        Severity: {p.severity} ({p.cvss_v3_score ?? "—"})
                      </div>
                      <div className="text-slate-700">IP: {p.ip_obfuscated}</div>
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
      </div>
    </div>
  );
}

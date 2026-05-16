import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import clsx from "clsx";
import { motion } from "framer-motion";
import { newsApi } from "@/api/endpoints";
import type { NewsArticle, NewsListResponse } from "@/types";
import { timeAgo } from "@/utils/format";

type SortMode = "latest" | "category";

const CATEGORY_STYLE: Record<string, string> = {
  "Threat Intel": "bg-fuchsia-50 text-fuchsia-700 border-fuchsia-200",
  Vulnerabilities: "bg-red-50 text-red-700 border-red-200",
  "Malware / Ransomware": "bg-orange-50 text-orange-700 border-orange-200",
  "Breach / Incident": "bg-amber-50 text-amber-800 border-amber-200",
  "General Security": "bg-sky-50 text-sky-700 border-sky-200",
};

function categoryClass(cat: string) {
  return CATEGORY_STYLE[cat] || "bg-slate-100 text-slate-700 border-slate-200";
}

export default function NewsFeedPage() {
  const [data, setData] = useState<NewsListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [category, setCategory] = useState<string>("");
  const [search, setSearch] = useState<string>("");
  const [sort, setSort] = useState<SortMode>("latest");

  const load = useCallback(
    async (opts: { silent?: boolean } = {}) => {
      if (!opts.silent) setLoading(true);
      try {
        const res = await newsApi.list({
          category: category || undefined,
          search: search.trim() || undefined,
          limit: 120,
        });
        setData(res);
        setError(null);
      } catch (e: any) {
        setError(e?.message || "Failed to load news");
      } finally {
        setLoading(false);
      }
    },
    [category, search],
  );

  // Tick a "now" state every 30s so relative "Last refreshed Xm ago" labels advance live.
  const [, setTick] = useState(0);
  const tickRef = useRef<number | null>(null);
  useEffect(() => {
    tickRef.current = window.setInterval(() => setTick((t) => t + 1), 30_000);
    return () => {
      if (tickRef.current) window.clearInterval(tickRef.current);
    };
  }, []);

  useEffect(() => {
    load();
    const interval = setInterval(() => load({ silent: true }), 10 * 60 * 1000);
    return () => clearInterval(interval);
  }, [load]);

  const handleRefresh = async () => {
    setRefreshing(true);
    try {
      await newsApi.refresh();
      await load({ silent: true });
    } catch (e: any) {
      setError(e?.response?.data?.detail || e?.message || "Refresh failed");
    } finally {
      setRefreshing(false);
    }
  };

  const items = useMemo(() => {
    if (!data) return [];
    const list = [...data.items];
    if (sort === "category") {
      list.sort((a, b) => {
        const c = a.category.localeCompare(b.category);
        if (c !== 0) return c;
        return new Date(b.published_at).getTime() - new Date(a.published_at).getTime();
      });
    } else {
      list.sort(
        (a, b) => new Date(b.published_at).getTime() - new Date(a.published_at).getTime(),
      );
    }
    return list;
  }, [data, sort]);

  const grouped = useMemo(() => {
    if (sort !== "category") return null;
    const map = new Map<string, NewsArticle[]>();
    for (const item of items) {
      const arr = map.get(item.category) || [];
      arr.push(item);
      map.set(item.category, arr);
    }
    return Array.from(map.entries());
  }, [items, sort]);

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="page-heading">Cybersecurity News Feed</h1>
          <div className="page-underline" />
          <p className="page-subtitle">
            Headlines from BleepingComputer, The Hacker News, Krebs and friends. Refreshed
            every 10 minutes · 48h retention · {data?.total ?? 0} stories on the wall
            {data?.last_refresh && (
              <>
                {" "}· Last refreshed{" "}
                <span className="font-semibold text-sentinel-navyDark">
                  {timeAgo(data.last_refresh)}
                </span>
              </>
            )}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleRefresh}
            disabled={refreshing}
            className="btn-gold"
          >
            {refreshing ? "Refreshing…" : "⟳ Refresh"}
          </button>
        </div>
      </div>

      <div className="panel-pad">
        <div className="flex flex-wrap items-end gap-3">
          <div className="flex-1 min-w-[220px]">
            <label className="label">Search</label>
            <input
              className="input"
              placeholder="Keyword, vendor, CVE…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") load();
              }}
            />
          </div>
          <div>
            <label className="label">View</label>
            <div className="flex rounded-lg border border-sentinel-border bg-white p-0.5">
              {(["latest", "category"] as const).map((m) => (
                <button
                  key={m}
                  onClick={() => setSort(m)}
                  className={clsx(
                    "rounded-md px-3 py-1.5 text-xs font-semibold uppercase tracking-wider transition",
                    sort === m
                      ? "bg-sentinel-navy text-white"
                      : "text-slate-500 hover:text-sentinel-navyDark",
                  )}
                >
                  {m === "latest" ? "Latest First" : "By Category"}
                </button>
              ))}
            </div>
          </div>
        </div>

        <div className="mt-3 flex flex-wrap gap-2">
          <button
            onClick={() => setCategory("")}
            className={clsx(
              "badge border px-3 py-1",
              category === ""
                ? "bg-sentinel-navy text-white border-sentinel-navy"
                : "bg-white text-slate-600 border-sentinel-border hover:border-sentinel-navy",
            )}
          >
            All ({data?.total ?? 0})
          </button>
          {(data?.categories || []).map((cat) => (
            <button
              key={cat}
              onClick={() => setCategory(cat)}
              className={clsx(
                "badge border px-3 py-1",
                category === cat
                  ? categoryClass(cat)
                  : "bg-white text-slate-600 border-sentinel-border hover:border-sentinel-navy",
              )}
            >
              {cat} ({data?.counts_by_category[cat] ?? 0})
            </button>
          ))}
        </div>
      </div>

      {error && <div className="panel-pad text-red-600">{error}</div>}
      {loading && !data && <div className="panel-pad text-slate-400">Loading news…</div>}

      {data && !grouped && (
        <NewsGrid items={items} />
      )}
      {data && grouped && (
        <div className="space-y-6">
          {grouped.map(([cat, articles]) => (
            <div key={cat}>
              <div className="mb-2 flex items-center gap-3">
                <span className={clsx("badge border", categoryClass(cat))}>{cat}</span>
                <span className="text-xs text-slate-500">{articles.length} stories</span>
              </div>
              <NewsGrid items={articles} />
            </div>
          ))}
        </div>
      )}

      {data && items.length === 0 && (
        <div className="panel-pad text-center text-slate-400">
          No news matches your filters. Try clearing search or switching category.
        </div>
      )}
    </div>
  );
}

function NewsGrid({ items }: { items: NewsArticle[] }) {
  const newest = items[0]?.id;
  return (
    <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
      {items.map((item, idx) => (
        <motion.a
          key={item.id}
          href={item.url}
          target="_blank"
          rel="noreferrer"
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: Math.min(idx * 0.02, 0.3) }}
          className={clsx(
            "panel flex flex-col gap-3 p-5 transition hover:-translate-y-0.5 hover:shadow-card",
            item.id === newest && "ring-2 ring-sentinel-gold",
          )}
        >
          <div className="flex items-start justify-between gap-3">
            <span className={clsx("badge border", categoryClass(item.category))}>
              {item.category}
            </span>
            <span className="text-[11px] uppercase tracking-wider text-slate-400">
              {timeAgo(item.published_at)}
            </span>
          </div>
          <h3 className="text-base font-semibold leading-snug text-sentinel-navyDark">
            {item.title}
          </h3>
          {item.description && (
            <p className="line-clamp-3 text-sm text-slate-500">{item.description}</p>
          )}
          <div className="mt-auto flex items-center justify-between border-t border-sentinel-border pt-3 text-xs">
            <span className="font-semibold text-sentinel-navy">{item.source}</span>
            <span className="text-sentinel-gold">Read →</span>
          </div>
        </motion.a>
      ))}
    </div>
  );
}

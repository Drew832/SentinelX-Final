/**
 * SentinelX-branded PDF report generator (jsPDF, raw canvas).
 *
 * The output strictly follows the approved brand template:
 *
 *   ZONE 1 — Header (top ~28% of page)
 *     • Gradient: dark purple (#2D1B4E) → amber/gold (#F5A623)
 *     • Wordmark: white "SENTINEL" + gold "X" (no IX suffix)
 *     • Tagline: DETECT. PRIORITIZE. REMEDIATE. (gold spaced caps)
 *     • Title: "Intelligence Report" (centered, bold, white)
 *     • Decorative concentric-circle radar (low-opacity gold strokes)
 *
 *   ZONE 2 — Body (remaining ~72%)
 *     • Background: dark navy (#0D1B2A) full bleed, no white
 *     • Headings: gold (#F5A623), bold, ~14pt, with thin gold rule
 *     • Body copy: light grey (#CBD5E1)
 *     • Severity cards: green / orange / dark-red rounded rectangles
 *     • Bottom-right decorative gold chevron line art (low opacity)
 *
 *   FOOTER
 *     • Thin gold rule
 *     • "SentinelX – Intelligence Report" bottom-left
 *     • Page number bottom-right
 *
 * Implementation notes
 * --------------------
 * We deliberately use raw jsPDF canvas calls (rect, text, ellipse, lines)
 * so every pixel is brand-controlled. jsPDF-AutoTable is reserved for the
 * (now retired) technical report variant — the executive PDF this module
 * produces draws everything by hand.
 */
import jsPDF from "jspdf";

// ── Brand tokens ────────────────────────────────────────────────────────────
const NAVY = [13, 27, 42] as const; // #0D1B2A  body bg
const NAVY_SOFT = [22, 40, 60] as const; // mild lift for layered surfaces
const PURPLE_DARK = [45, 27, 78] as const; // #2D1B4E  header left
const GOLD = [245, 166, 35] as const; // #F5A623
const GOLD_SOFT = [252, 211, 77] as const;
const WHITE = [255, 255, 255] as const;
const SLATE = [203, 213, 225] as const; // #CBD5E1 body copy
const GREEN_1 = [34, 197, 94] as const; // #22C55E
const GREEN_2 = [22, 163, 74] as const; // #16A34A (border / accent)
const ORANGE_1 = [249, 115, 22] as const; // #F97316
const ORANGE_2 = [234, 88, 12] as const; // #EA580C
const RED_1 = [190, 18, 60] as const; // #BE123C
const RED_2 = [159, 18, 57] as const; // #9F1239

const PAGE_W = 210; // A4 mm (portrait)
const PAGE_H = 297;
const MARGIN = 14;
const CONTENT_W = PAGE_W - MARGIN * 2;
const HEADER_H = 80;
const BODY_TOP = HEADER_H;
const FOOTER_BAND = 18;

type RGB = readonly [number, number, number];

// ── Low-level helpers ───────────────────────────────────────────────────────

function fill(doc: jsPDF, [r, g, b]: RGB) {
  doc.setFillColor(r, g, b);
}
function stroke(doc: jsPDF, [r, g, b]: RGB) {
  doc.setDrawColor(r, g, b);
}
function textColor(doc: jsPDF, [r, g, b]: RGB) {
  doc.setTextColor(r, g, b);
}

/**
 * Set graphics-state opacity if the runtime supports it. jsPDF exposes
 * `GState` only when the underlying PDF spec extension is available; older
 * builds silently no-op, in which case we just skip the alpha adjustment
 * to keep the report from crashing.
 */
function withAlpha(doc: jsPDF, alpha: number, draw: () => void) {
  const anyDoc = doc as any;
  let restore: (() => void) | null = null;
  try {
    if (typeof anyDoc.setGState === "function" && typeof anyDoc.GState === "function") {
      anyDoc.setGState(anyDoc.GState({ opacity: alpha }));
      restore = () => anyDoc.setGState(anyDoc.GState({ opacity: 1 }));
    }
  } catch {
    /* GState unavailable — render at full opacity. */
  }
  try {
    draw();
  } finally {
    restore?.();
  }
}

// ── Header zone ─────────────────────────────────────────────────────────────

function drawHeader(doc: jsPDF) {
  // Gradient approximation: 24 vertical bands purple → gold.
  const steps = 24;
  for (let i = 0; i < steps; i++) {
    const t = i / (steps - 1);
    const r = Math.round(PURPLE_DARK[0] + t * (GOLD[0] - PURPLE_DARK[0]));
    const g = Math.round(PURPLE_DARK[1] + t * (GOLD[1] - PURPLE_DARK[1]));
    const b = Math.round(PURPLE_DARK[2] + t * (GOLD[2] - PURPLE_DARK[2]));
    doc.setFillColor(r, g, b);
    doc.rect(i * (PAGE_W / steps), 0, PAGE_W / steps + 0.6, HEADER_H, "F");
  }

  // Decorative concentric radar (top right).
  withAlpha(doc, 0.32, () => {
    stroke(doc, GOLD);
    doc.setLineWidth(0.5);
    const cx = PAGE_W - 28;
    const cy = 38;
    [14, 24, 34, 44].forEach((r) => doc.ellipse(cx, cy, r, r, "S"));
    doc.line(cx - 50, cy, cx + 10, cy);
    doc.line(cx, cy - 50, cx, cy + 10);
    fill(doc, GOLD);
    doc.circle(cx, cy, 1.4, "F");
  });

  // Wordmark: SENTINEL (white) + X (gold).
  doc.setFont("helvetica", "bold");
  doc.setFontSize(32);
  textColor(doc, WHITE);
  doc.text("SENTINEL", MARGIN, 34);
  const sentinelW = doc.getTextWidth("SENTINEL");
  textColor(doc, GOLD);
  doc.text("X", MARGIN + sentinelW + 1, 34);

  // Tagline (gold, spaced caps).
  doc.setFont("helvetica", "bold");
  doc.setFontSize(7);
  textColor(doc, GOLD);
  doc.text("DETECT.   PRIORITIZE.   REMEDIATE.", MARGIN, 42);

  // Divider line under tagline.
  stroke(doc, GOLD);
  doc.setLineWidth(0.3);
  doc.line(MARGIN, 48, PAGE_W - MARGIN, 48);

  // Centered report title.
  doc.setFont("helvetica", "bold");
  doc.setFontSize(20);
  textColor(doc, WHITE);
  doc.text("Intelligence Report", PAGE_W / 2, 64, { align: "center" });
}

// ── Body background ─────────────────────────────────────────────────────────

function drawBody(doc: jsPDF) {
  fill(doc, NAVY);
  doc.rect(0, BODY_TOP, PAGE_W, PAGE_H - BODY_TOP, "F");
}

// ── Section heading with gold underline ─────────────────────────────────────

function drawSectionHeading(doc: jsPDF, title: string, y: number) {
  doc.setFont("helvetica", "bold");
  doc.setFontSize(14);
  textColor(doc, GOLD);
  doc.text(title.toUpperCase(), MARGIN, y);
  stroke(doc, GOLD);
  doc.setLineWidth(0.45);
  doc.line(MARGIN, y + 2.2, PAGE_W - MARGIN, y + 2.2);
}

// ── Severity / risk card ────────────────────────────────────────────────────

function drawSeverityCard(
  doc: jsPDF,
  x: number,
  y: number,
  w: number,
  h: number,
  fillColor: RGB,
  borderColor: RGB,
  count: number | string,
  label: string,
) {
  fill(doc, fillColor);
  stroke(doc, borderColor);
  doc.setLineWidth(0.6);
  doc.roundedRect(x, y, w, h, 4, 4, "FD");

  doc.setFont("helvetica", "bold");
  doc.setFontSize(22);
  textColor(doc, WHITE);
  doc.text(String(count), x + w / 2, y + h * 0.5, { align: "center" });

  doc.setFont("helvetica", "bold");
  doc.setFontSize(8);
  textColor(doc, WHITE);
  doc.text(label.toUpperCase(), x + w / 2, y + h * 0.78, { align: "center" });
}

// ── Bottom-right decorative chevron line art ────────────────────────────────

function drawDecorativeChevrons(doc: jsPDF) {
  withAlpha(doc, 0.22, () => {
    stroke(doc, GOLD);
    doc.setLineWidth(1.1);
    const baseX = PAGE_W - 4;
    const baseY = PAGE_H - 6;
    for (let i = 0; i < 5; i++) {
      const off = i * 14;
      doc.lines(
        [
          [-26, -26],
          [26, -26],
        ],
        baseX - off,
        baseY - off,
        [1, 1],
        "S",
      );
    }
  });
}

// ── Right-column accent block (chart placeholder / image holder) ────────────

function drawAccentBlock(doc: jsPDF, x: number, y: number, w: number, h: number) {
  // Soft layered surface so an embedded image, when present, sits on a panel.
  fill(doc, NAVY_SOFT);
  stroke(doc, GOLD);
  doc.setLineWidth(0.4);
  doc.roundedRect(x, y, w, h, 5, 5, "FD");

  // Subtle gold corner accent so the rectangle doesn't look empty when
  // rendered without an embedded chart.
  withAlpha(doc, 0.65, () => {
    stroke(doc, GOLD);
    doc.setLineWidth(0.7);
    doc.line(x + 4, y + 4, x + 18, y + 4);
    doc.line(x + 4, y + 4, x + 4, y + 18);
    doc.line(x + w - 4, y + h - 4, x + w - 18, y + h - 4);
    doc.line(x + w - 4, y + h - 4, x + w - 4, y + h - 18);
  });
}

// ── Footer ──────────────────────────────────────────────────────────────────

function drawFooter(doc: jsPDF, pageNum: number, totalPages: number) {
  const y = PAGE_H - 6;
  stroke(doc, GOLD);
  doc.setLineWidth(0.3);
  doc.line(MARGIN, y - 5, PAGE_W - MARGIN, y - 5);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(7);
  textColor(doc, GOLD);
  doc.text("SentinelX  \u2013  Intelligence Report", MARGIN, y);
  doc.setFont("helvetica", "normal");
  doc.text(`Page ${pageNum} / ${totalPages}`, PAGE_W - MARGIN, y, { align: "right" });
}

// ── Public types ────────────────────────────────────────────────────────────

export interface ReportSeverityBreakdown {
  low: number;
  medium: number;
  high: number;
  critical: number;
}

export interface ReportMeta {
  /** e.g. "Acme Corp" or the org profile name. */
  organisation?: string;
  /** Asset / system being reported on. */
  asset?: string;
  /** ISO date string for the start of the reporting window. */
  startDate?: string;
  /** ISO date string for the end of the reporting window. */
  endDate?: string;
  /** Optional username / system that generated the report. */
  generatedBy?: string;
  /** Optional ISO timestamp; defaults to "now". */
  generatedAt?: string;
}

export interface ReportData {
  title?: string;
  brief: string;
  recommendation: string | string[];
  severity: ReportSeverityBreakdown;
  /** Optional base64-encoded PNG (e.g. exported from a Recharts canvas). */
  chartImageBase64?: string;
  /** Brand metadata rendered as a side block on the cover page. */
  meta?: ReportMeta;
  /** Optional download filename override. */
  filename?: string;
}

// ── Layout helpers for body content ─────────────────────────────────────────

function paragraphify(doc: jsPDF, text: string, width: number): string[] {
  return doc.splitTextToSize(text, width);
}

function recommendationLines(
  rec: string | string[],
  doc: jsPDF,
  width: number,
): string[] {
  const items = Array.isArray(rec) ? rec : [rec];
  const out: string[] = [];
  items.forEach((entry, idx) => {
    const prefix = items.length > 1 ? `${idx + 1}.  ` : "";
    const wrapped = paragraphify(doc, `${prefix}${entry}`, width);
    out.push(...wrapped);
    if (idx < items.length - 1) out.push("");
  });
  return out;
}

function drawMetaStrip(doc: jsPDF, meta: ReportMeta | undefined, y: number) {
  if (!meta) return y;
  const generatedAt = meta.generatedAt || new Date().toISOString();
  const items: { label: string; value: string }[] = [];
  if (meta.organisation) items.push({ label: "Organisation", value: meta.organisation });
  if (meta.asset) items.push({ label: "Asset", value: meta.asset });
  if (meta.startDate && meta.endDate)
    items.push({
      label: "Window",
      value: `${meta.startDate}  \u2192  ${meta.endDate}`,
    });
  items.push({ label: "Generated", value: generatedAt.slice(0, 19).replace("T", " ") + " UTC" });
  if (meta.generatedBy) items.push({ label: "By", value: meta.generatedBy });

  if (!items.length) return y;

  const rowH = 6;
  const cardH = items.length * rowH + 8;
  fill(doc, NAVY_SOFT);
  stroke(doc, GOLD);
  doc.setLineWidth(0.3);
  doc.roundedRect(MARGIN, y, CONTENT_W, cardH, 3, 3, "FD");

  let cursor = y + 6;
  items.forEach((it) => {
    doc.setFont("helvetica", "bold");
    doc.setFontSize(7.5);
    textColor(doc, GOLD);
    doc.text(it.label.toUpperCase(), MARGIN + 4, cursor);
    doc.setFont("helvetica", "normal");
    textColor(doc, SLATE);
    doc.text(it.value, MARGIN + 36, cursor);
    cursor += rowH;
  });
  return y + cardH;
}

// ── Page-flow helper ────────────────────────────────────────────────────────

function startNewPage(doc: jsPDF) {
  doc.addPage();
  drawHeader(doc);
  drawBody(doc);
  drawDecorativeChevrons(doc);
}

// ── MAIN EXPORT ─────────────────────────────────────────────────────────────

/**
 * Render the SentinelX Intelligence Report and save it.
 *
 * Always returns the jsPDF instance so callers that want to embed the
 * generated PDF (instead of triggering a download) can reuse it.
 */
export function generateSentinelXReport(data: ReportData): jsPDF {
  const doc = new jsPDF({ unit: "mm", format: "a4", orientation: "portrait" });

  // ── Page 1 ───────────────────────────────────────────────
  drawHeader(doc);
  drawBody(doc);
  drawDecorativeChevrons(doc);

  let cursorY = BODY_TOP + 10;

  // Optional metadata strip (organisation, window, etc.).
  cursorY = drawMetaStrip(doc, data.meta, cursorY);
  if (data.meta) cursorY += 8;

  // Risk Breakdown — three severity cards
  drawSectionHeading(doc, "Risk Breakdown", cursorY);
  cursorY += 8;

  const cardH = 28;
  const cardGap = 6;
  const cardW = (CONTENT_W - cardGap * 2) / 3;
  const cardY = cursorY;
  const high = (data.severity.high || 0) + (data.severity.critical || 0);

  drawSeverityCard(
    doc,
    MARGIN,
    cardY,
    cardW,
    cardH,
    GREEN_1,
    GREEN_2,
    data.severity.low || 0,
    "Low / Safe",
  );
  drawSeverityCard(
    doc,
    MARGIN + cardW + cardGap,
    cardY,
    cardW,
    cardH,
    ORANGE_1,
    ORANGE_2,
    data.severity.medium || 0,
    "Medium",
  );
  drawSeverityCard(
    doc,
    MARGIN + (cardW + cardGap) * 2,
    cardY,
    cardW,
    cardH,
    RED_1,
    RED_2,
    high,
    "High / Critical",
  );

  cursorY = cardY + cardH + 12;

  // ── Brief + accent block ───────────────────────────────
  drawSectionHeading(doc, "Brief", cursorY);
  cursorY += 8;

  const leftColW = CONTENT_W * 0.6;
  const colGap = 6;
  const rightColX = MARGIN + leftColW + colGap;
  const rightColW = CONTENT_W - leftColW - colGap;
  const accentY = cursorY;
  const accentH = 78;

  drawAccentBlock(doc, rightColX, accentY, rightColW, accentH);
  if (data.chartImageBase64) {
    try {
      doc.addImage(
        data.chartImageBase64,
        "PNG",
        rightColX + 3,
        accentY + 3,
        rightColW - 6,
        accentH - 6,
      );
    } catch {
      // Bad base64 — silently fall back to the empty accent panel.
    }
  } else {
    // Decorative gold "X" target inside the accent block.
    withAlpha(doc, 0.55, () => {
      stroke(doc, GOLD);
      doc.setLineWidth(0.6);
      const cx = rightColX + rightColW / 2;
      const cy = accentY + accentH / 2;
      [22, 16, 10, 5].forEach((r) => doc.ellipse(cx, cy, r, r, "S"));
      fill(doc, GOLD);
      doc.circle(cx, cy, 1.6, "F");
    });
  }

  doc.setFont("helvetica", "normal");
  doc.setFontSize(9.5);
  textColor(doc, SLATE);
  const briefLines = paragraphify(doc, data.brief || "No briefing available.", leftColW);
  doc.text(briefLines, MARGIN, cursorY + 4);
  const briefHeight = briefLines.length * 5 + 4;
  cursorY += Math.max(briefHeight, accentH) + 8;

  // ── Recommendation ─────────────────────────────────────
  drawSectionHeading(doc, "Recommendation", cursorY);
  cursorY += 8;

  doc.setFont("helvetica", "normal");
  doc.setFontSize(9.5);
  textColor(doc, SLATE);
  const recLines = recommendationLines(data.recommendation, doc, CONTENT_W);

  // Page-overflow handling for long recommendation lists.
  const lineH = 5;
  const safeBottom = PAGE_H - FOOTER_BAND - 4;
  for (const line of recLines) {
    if (cursorY > safeBottom) {
      startNewPage(doc);
      cursorY = BODY_TOP + 14;
      drawSectionHeading(doc, "Recommendation (cont.)", cursorY);
      cursorY += 8;
      doc.setFont("helvetica", "normal");
      doc.setFontSize(9.5);
      textColor(doc, SLATE);
    }
    doc.text(line, MARGIN, cursorY);
    cursorY += lineH;
  }

  // Footers (after all pages exist).
  const totalPages = (doc as any).internal.getNumberOfPages
    ? (doc as any).internal.getNumberOfPages()
    : 1;
  for (let p = 1; p <= totalPages; p++) {
    doc.setPage(p);
    drawFooter(doc, p, totalPages);
  }

  const filename = data.filename || "SentinelX-Intelligence-Report.pdf";
  doc.save(filename);
  return doc;
}

// Keep secondary palette tokens exported for downstream consumers (e.g.
// custom report wrappers that want to match the brand colours exactly).
export const SENTINELX_BRAND = {
  NAVY,
  PURPLE_DARK,
  GOLD,
  GOLD_SOFT,
  WHITE,
  SLATE,
  GREEN_1,
  GREEN_2,
  ORANGE_1,
  ORANGE_2,
  RED_1,
  RED_2,
} as const;

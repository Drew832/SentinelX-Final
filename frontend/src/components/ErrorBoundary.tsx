import { Component, type ErrorInfo, type ReactNode } from "react";

interface Props {
  /** Optional named scope so the same boundary can be reused in multiple
   *  places without overwriting each other's UI. */
  scope?: string;
  children: ReactNode;
  /** When provided, the boundary renders this instead of the default
   *  fallback. Useful for wrapping single widgets. */
  fallback?: (error: Error, reset: () => void) => ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

/**
 * Global React Error Boundary.
 *
 * React 18 will unmount the entire tree when a render throws, which is
 * exactly how SentinelX users were ending up on a blank white screen
 * after clicking Register/Login. Wrapping the app (and any
 * high-blast-radius widget) in this boundary guarantees that the user
 * always sees a recoverable fallback instead of an empty document, and
 * gives them a one-click "Reload" out of any transient crash.
 *
 * The fallback intentionally avoids using any of the app's design
 * tokens beyond inline style — if the CSS pipeline itself crashed, we
 * still want a usable error screen.
 */
export default class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false, error: null };

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    // eslint-disable-next-line no-console
    console.error(
      `[SentinelX:${this.props.scope || "app"}] Unhandled render error:`,
      error,
      info.componentStack,
    );
  }

  reset = () => this.setState({ hasError: false, error: null });

  hardReload = () => {
    try {
      window.location.assign("/");
    } catch {
      window.location.reload();
    }
  };

  render() {
    if (!this.state.hasError) return this.props.children;

    if (this.props.fallback && this.state.error) {
      return this.props.fallback(this.state.error, this.reset);
    }

    return (
      <div
        role="alert"
        style={{
          minHeight: "100vh",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          background:
            "linear-gradient(135deg, #060d1e 0%, #0f1d3a 60%, #1c3b7a 100%)",
          color: "#fff",
          fontFamily:
            "Inter, system-ui, -apple-system, Segoe UI, Roboto, sans-serif",
          padding: "24px",
        }}
      >
        <div
          style={{
            maxWidth: 520,
            width: "100%",
            background: "rgba(255,255,255,0.06)",
            border: "1px solid rgba(255,255,255,0.12)",
            borderRadius: 16,
            padding: 32,
            backdropFilter: "blur(12px)",
            boxShadow: "0 18px 60px rgba(0,0,0,0.5)",
          }}
        >
          <div
            style={{
              fontSize: 32,
              fontWeight: 900,
              letterSpacing: "-0.5px",
              lineHeight: 1,
              marginBottom: 8,
            }}
          >
            <span style={{ color: "#fff" }}>SENTINEL</span>
            <span style={{ color: "#F5A623", marginLeft: 2 }}>X</span>
          </div>
          <div
            style={{
              fontSize: 10,
              fontWeight: 700,
              letterSpacing: "0.3em",
              color: "rgba(255,255,255,0.7)",
              textTransform: "uppercase",
              marginBottom: 24,
            }}
          >
            Detect · Prioritize · Remediate
          </div>

          <h1 style={{ fontSize: 22, fontWeight: 800, margin: "0 0 8px" }}>
            Something went wrong
          </h1>
          <p
            style={{
              fontSize: 14,
              color: "rgba(255,255,255,0.75)",
              lineHeight: 1.55,
              margin: "0 0 16px",
            }}
          >
            The SentinelX console hit an unexpected error while rendering
            this screen. Your data is safe — try recovering from this view
            or reloading the workspace.
          </p>

          {this.state.error?.message && (
            <pre
              style={{
                background: "rgba(0,0,0,0.35)",
                border: "1px solid rgba(255,255,255,0.08)",
                borderRadius: 8,
                padding: 12,
                fontSize: 12,
                color: "#fbbf24",
                whiteSpace: "pre-wrap",
                wordBreak: "break-word",
                margin: "0 0 20px",
                maxHeight: 160,
                overflow: "auto",
              }}
            >
              {this.state.error.message}
            </pre>
          )}

          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <button
              type="button"
              onClick={this.reset}
              style={{
                flex: "1 1 160px",
                padding: "12px 16px",
                borderRadius: 10,
                border: "1px solid rgba(255,255,255,0.2)",
                background: "rgba(255,255,255,0.08)",
                color: "#fff",
                fontWeight: 600,
                cursor: "pointer",
              }}
            >
              Try again
            </button>
            <button
              type="button"
              onClick={this.hardReload}
              style={{
                flex: "1 1 160px",
                padding: "12px 16px",
                borderRadius: 10,
                border: "none",
                background: "linear-gradient(90deg,#F5A623,#fbbf24)",
                color: "#0f1d3a",
                fontWeight: 700,
                cursor: "pointer",
              }}
            >
              Reload SentinelX
            </button>
          </div>
        </div>
      </div>
    );
  }
}

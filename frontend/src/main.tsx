import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import App from "./App";
import { AuthProvider } from "./context/AuthContext";
import ErrorBoundary from "./components/ErrorBoundary";
import "leaflet/dist/leaflet.css";
import "./styles/index.css";

// Top-level ErrorBoundary catches any uncaught render error in the entire
// SentinelX shell. Without it, React 18 unmounts the whole tree on a
// component throw and the user lands on a blank white page (the original
// /register regression). Inner pages can also wrap themselves in their own
// boundary via `import ErrorBoundary from "@/components/ErrorBoundary"`.
ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ErrorBoundary scope="root">
      <BrowserRouter>
        <AuthProvider>
          <ErrorBoundary scope="app">
            <App />
          </ErrorBoundary>
        </AuthProvider>
      </BrowserRouter>
    </ErrorBoundary>
  </React.StrictMode>,
);

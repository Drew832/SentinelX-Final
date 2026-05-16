import { Navigate, Route, Routes } from "react-router-dom";
import AppShell from "@/components/layout/AppShell";
import ProtectedRoute from "@/components/auth/ProtectedRoute";
import LoginPage from "@/pages/LoginPage";
import RegisterPage from "@/pages/RegisterPage";
import DashboardPage from "@/pages/DashboardPage";
import CveExplorerPage from "@/pages/CveExplorerPage";
import ThreatMapPage from "@/pages/ThreatMapPage";
import AssistantPage from "@/pages/AssistantPage";
import ReportsPage from "@/pages/ReportsPage";
import NewsFeedPage from "@/pages/NewsFeedPage";
import ProfilesPage from "@/pages/ProfilesPage";
import KevPage from "@/pages/KevPage";
import PoliciesPage from "@/pages/PoliciesPage";
import CompliancePage from "@/pages/CompliancePage";
import AssetHealthPage from "@/pages/AssetHealthPage";
import AttackSurfacePage from "@/pages/AttackSurfacePage";
import AccountPage from "@/pages/AccountPage";
import ExecutiveReportPage from "@/pages/ExecutiveReportPage";
import TechnicalReportPage from "@/pages/TechnicalReportPage";

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegisterPage />} />

      <Route
        element={
          <ProtectedRoute allowGuest>
            <AppShell />
          </ProtectedRoute>
        }
      >
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard" element={<DashboardPage />} />
        <Route path="cves" element={<CveExplorerPage />} />
        <Route path="kev" element={<KevPage />} />
        <Route path="threat-map" element={<ThreatMapPage />} />
        <Route path="attack-surface" element={<AttackSurfacePage />} />
        <Route path="asset-health" element={<AssetHealthPage />} />
        <Route path="compliance" element={<CompliancePage />} />
        <Route path="policies" element={<PoliciesPage />} />
        <Route path="news" element={<NewsFeedPage />} />
        <Route
          path="profiles"
          element={
            <ProtectedRoute allowGuest={false}>
              <ProfilesPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="assistant"
          element={
            <ProtectedRoute allowGuest={false} requiredRole="user">
              <AssistantPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="account"
          element={
            <ProtectedRoute allowGuest={false}>
              <AccountPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="reports/executive/:id"
          element={
            <ProtectedRoute allowGuest={false}>
              <ExecutiveReportPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="reports/technical/:id"
          element={
            <ProtectedRoute allowGuest={false}>
              <TechnicalReportPage />
            </ProtectedRoute>
          }
        />
        <Route path="reports" element={<ReportsPage />} />
      </Route>

      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  );
}

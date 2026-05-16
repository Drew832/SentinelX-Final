import { Navigate, useLocation } from "react-router-dom";
import type { ReactNode } from "react";
import { useAuth } from "@/context/AuthContext";

interface Props {
  children: ReactNode;
  allowGuest?: boolean;
  requiredRole?: "admin" | "user";
}

export default function ProtectedRoute({ children, allowGuest = true, requiredRole }: Props) {
  const { user, isGuest, loading } = useAuth();
  const location = useLocation();

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center text-slate-400">
        Authenticating…
      </div>
    );
  }

  if (!user && !(allowGuest && isGuest)) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  if (requiredRole) {
    if (!user) {
      return <Navigate to="/login" state={{ from: location }} replace />;
    }
    if (requiredRole === "admin" && user.role !== "admin") {
      return (
        <div className="panel-pad text-center">
          <h2 className="text-xl font-semibold text-sentinel-gold">Restricted area</h2>
          <p className="mt-2 text-slate-400">
            Admin privileges required to view this page.
          </p>
        </div>
      );
    }
  }

  return <>{children}</>;
}

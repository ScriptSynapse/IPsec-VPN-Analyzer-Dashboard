import { Navigate, Route, Routes } from "react-router-dom";
import { UploadPage } from "./pages/UploadPage.jsx";
import { SessionsListPage } from "./pages/SessionsListPage.jsx";
import { SessionDetailPage } from "./pages/SessionDetailPage.jsx";
import { TunnelsListPage } from "./pages/TunnelsListPage.jsx";
import { TunnelDetailPage } from "./pages/TunnelDetailPage.jsx";
import { PoliciesPage } from "./pages/PoliciesPage.jsx";
import { ReportsPage } from "./pages/ReportsPage.jsx";
import { AgentsPage } from "./pages/AgentsPage.jsx";
import { TopologyPage } from "./pages/TopologyPage.jsx";

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Navigate to="/sessions" replace />} />
      <Route path="/sessions" element={<SessionsListPage />} />
      <Route path="/sessions/upload" element={<UploadPage />} />
      <Route path="/sessions/:id" element={<SessionDetailPage />} />
      <Route path="/tunnels" element={<TunnelsListPage />} />
      <Route path="/tunnels/:tunnelId" element={<TunnelDetailPage />} />
      <Route path="/agents" element={<AgentsPage />} />
      <Route path="/topology" element={<TopologyPage />} />
      <Route path="/policies" element={<PoliciesPage />} />
      <Route path="/reports" element={<ReportsPage />} />
      <Route path="*" element={<Navigate to="/sessions" replace />} />
    </Routes>
  );
}

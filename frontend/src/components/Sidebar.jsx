import { NavLink } from "react-router-dom";
import { Icons } from "./Icons.jsx";
import { BackendUrlField } from "./BackendUrlField.jsx";

const NAV_ITEMS = [
  { section: "Ingestion", items: [{ to: "/sessions/upload", label: "Upload Sandbox", Icon: Icons.Briefcase }] },
  {
    section: "Analysis Objects",
    items: [
      { to: "/sessions", label: "Captured Sessions", Icon: Icons.Database },
      { to: "/tunnels", label: "Tunnels (Observer Profiles)", Icon: Icons.Network },
      { to: "/policies", label: "Custom Policies", Icon: Icons.ShieldAlert },
    ],
  },
  {
    section: "Monitoring",
    items: [
      { to: "/agents", label: "Agents", Icon: Icons.Server },
      { to: "/topology", label: "Global Topology", Icon: Icons.Globe },
    ],
  },
  { section: "Output", items: [{ to: "/reports", label: "Assessment Reports", Icon: Icons.FileText }] },
];

function NavItem({ to, label, Icon }) {
  return (
    <NavLink
      to={to}
      end={to === "/sessions"}
      className={({ isActive }) =>
        `flex items-center px-2 py-2 text-sm font-medium rounded-lg ${
          isActive ? "bg-slate-100 text-apple-text" : "text-slate-600 hover:bg-slate-100 hover:text-apple-text"
        }`
      }
    >
      <Icon />
      <span className="ml-3">{label}</span>
    </NavLink>
  );
}

export function Sidebar() {
  return (
    <aside className="w-64 flex flex-col h-screen fixed bg-white border-r border-apple-border shadow-[1px_0_0_0_rgba(0,0,0,0.03)] z-10">
      <div className="h-14 flex items-center px-6 border-b border-apple-border mt-1">
        <h1 className="font-semibold tracking-tight text-base flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-apple-text block"></span>
          NTRO Analysis Desk
        </h1>
      </div>
      <nav className="flex-1 overflow-y-auto py-6 px-4 space-y-1">
        {NAV_ITEMS.map((group) => (
          <div key={group.section} className="mb-6 last:mb-0">
            <p className="px-2 text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">{group.section}</p>
            {group.items.map((item) => (
              <NavItem key={item.to} {...item} />
            ))}
          </div>
        ))}
      </nav>
      <BackendUrlField />
    </aside>
  );
}

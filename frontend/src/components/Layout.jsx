import { Sidebar } from "./Sidebar.jsx";

export function Layout({ children }) {
  return (
    <div className="flex bg-apple-bg min-h-screen">
      <Sidebar />
      <main className="ml-64 flex-1 flex flex-col min-h-screen relative">{children}</main>
    </div>
  );
}

export function PageHeader({ crumbs, title, badge, actions }) {
  return (
    <header className="h-16 px-8 flex items-center justify-between border-b border-apple-border bg-apple-bg/80 backdrop-blur-md sticky top-0 z-10">
      <div className="text-sm">
        {crumbs && <span className="text-slate-400">{crumbs} </span>}
        <span className="font-semibold text-slate-800 ml-1">{title}</span>
        {badge}
      </div>
      <div className="flex gap-2">{actions}</div>
    </header>
  );
}
